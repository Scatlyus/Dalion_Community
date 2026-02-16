/**
 * Dalion D3 Espionagem - Main Orchestrator
 * 
 * Threat Intelligence Enrichment with:
 * - VirusTotal integration
 * - AbuseIPDB integration
 * - Redis caching
 * - Rate limiting (Bottleneck)
 * - Conflict resolution
 */

import Redis from 'ioredis';
import Bottleneck from 'bottleneck';
import { VirusTotalClient } from './clients/virustotal';
import { AbuseIPDBClient } from './clients/abuseipdb';
import {
  EnrichmentRequest,
  EnrichmentResult,
  EnrichedIOC,
  IOC,
  D3Config,
  CacheEntry,
  EnrichmentError
} from './types';

export class DalionEspionagem {
  private vtClient: VirusTotalClient;
  private abuseIPDBClient: AbuseIPDBClient;
  private redis?: Redis;
  private config: D3Config;

  // Rate limiters
  private vtLimiter: Bottleneck;
  private abuseIPDBLimiter: Bottleneck;

  // Statistics
  private stats = {
    cache_hits: 0,
    cache_misses: 0,
    vt_calls: 0,
    abuseipdb_calls: 0,
    errors: 0
  };

  constructor(config: D3Config) {
    this.config = config;

    // Initialize API clients
    this.vtClient = new VirusTotalClient(
      config.virustotal.api_key,
      config.virustotal.timeout_ms
    );

    this.abuseIPDBClient = new AbuseIPDBClient(
      config.abuseipdb.api_key,
      config.abuseipdb.timeout_ms
    );

    // Initialize Redis if caching enabled
    if (config.cache.enabled) {
      this.redis = new Redis(config.cache.redis_url);

      this.redis.on('error', (err) => {
        console.error('[D3] Redis error:', err);
      });
    }

    // Initialize rate limiters
    this.vtLimiter = new Bottleneck({
      maxConcurrent: 1,
      minTime: Math.ceil(60000 / config.virustotal.rate_limit.max_requests),
      reservoir: config.virustotal.rate_limit.max_requests,
      reservoirRefreshAmount: config.virustotal.rate_limit.max_requests,
      reservoirRefreshInterval: config.virustotal.rate_limit.per_minutes * 60 * 1000
    });

    this.abuseIPDBLimiter = new Bottleneck({
      maxConcurrent: 1,
      minTime: Math.ceil(86400000 / config.abuseipdb.rate_limit.max_requests),
      reservoir: config.abuseipdb.rate_limit.max_requests,
      reservoirRefreshAmount: config.abuseipdb.rate_limit.max_requests,
      reservoirRefreshInterval: 86400000 // 24 hours
    });
  }

  /**
   * Main enrichment method
   */
  async enrich(request: EnrichmentRequest): Promise<EnrichmentResult> {
    // Reset stats
    this.stats = {
      cache_hits: 0,
      cache_misses: 0,
      vt_calls: 0,
      abuseipdb_calls: 0,
      errors: 0
    };

    const enrichedIOCs: EnrichedIOC[] = [];
    const useCache = request.use_cache !== false;

    // Process each IOC
    for (const ioc of request.iocs) {
      try {
        const enriched = await this.enrichSingleIOC(ioc, request, useCache);
        enrichedIOCs.push(enriched);
      } catch (error) {
        console.error(`[D3] Failed to enrich ${ioc.ioc_value}:`, error);
        this.stats.errors++;

        // Add minimal enrichment on error
        enrichedIOCs.push({
          ...ioc,
          enrichment: {},
          threat_score: 50, // Unknown
          confidence: 0,
          reputation: 'unknown',
          last_enriched: new Date().toISOString()
        });
      }
    }

    // Generate summary
    const summary = this.generateSummary(enrichedIOCs);

    return {
      enriched_iocs: enrichedIOCs,
      summary_report: summary
    };
  }

  /**
   * Enrich single IOC
   */
  private async enrichSingleIOC(
    ioc: IOC,
    request: EnrichmentRequest,
    useCache: boolean
  ): Promise<EnrichedIOC> {

    // Check cache first
    if (useCache) {
      const cached = await this.getFromCache(ioc);
      if (cached) {
        this.stats.cache_hits++;
        return {
          ...ioc,
          ...cached,
          last_enriched: cached.cached_at
        };
      }
    }

    this.stats.cache_misses++;

    // Determine which sources to use
    const sources = request.sources_priority || ['VirusTotal', 'AbuseIPDB'];

    const enrichment: EnrichedIOC['enrichment'] = {};
    const threatScores: number[] = [];

    // Enrich from each source
    for (const source of sources) {
      try {
        if (source === 'VirusTotal' && (ioc.ioc_type === 'domain' || ioc.ioc_type === 'IP')) {
          const vtData = await this.enrichViaVirusTotal(ioc);
          enrichment.virustotal = vtData;
          threatScores.push(VirusTotalClient.normalizeToThreatScore(vtData.reputation_score));
        }

        if (source === 'AbuseIPDB' && ioc.ioc_type === 'IP') {
          const abuseData = await this.enrichViaAbuseIPDB(ioc);
          enrichment.abuseipdb = abuseData;
          threatScores.push(abuseData.abuse_confidence_score);
        }
      } catch (error) {
        console.error(`[D3] ${source} enrichment failed for ${ioc.ioc_value}:`, error.message);
        // Continue with other sources
      }
    }

    // Calculate final threat score and reputation
    const threatScore = this.calculateThreatScore(threatScores, enrichment);
    const reputation = this.determineReputation(threatScore, enrichment);
    const confidence = this.calculateConfidence(ioc, threatScores.length);

    const enriched: EnrichedIOC = {
      ...ioc,
      enrichment,
      threat_score: threatScore,
      confidence,
      reputation,
      last_enriched: new Date().toISOString()
    };

    // Cache result
    if (useCache) {
      await this.saveToCache(enriched);
    }

    return enriched;
  }

  /**
   * Enrich via VirusTotal
   */
  private async enrichViaVirusTotal(ioc: IOC) {
    this.stats.vt_calls++;

    return this.vtLimiter.schedule(async () => {
      if (ioc.ioc_type === 'domain') {
        return await this.vtClient.getDomainReport(ioc.ioc_value);
      } else if (ioc.ioc_type === 'IP') {
        return await this.vtClient.getIPReport(ioc.ioc_value);
      }
      throw new Error(`Unsupported IOC type for VT: ${ioc.ioc_type}`);
    });
  }

  /**
   * Enrich via AbuseIPDB
   */
  private async enrichViaAbuseIPDB(ioc: IOC) {
    this.stats.abuseipdb_calls++;

    return this.abuseIPDBLimiter.schedule(async () => {
      return await this.abuseIPDBClient.checkIP(ioc.ioc_value);
    });
  }

  /**
   * Calculate final threat score from multiple sources
   */
  private calculateThreatScore(
    scores: number[],
    enrichment: EnrichedIOC['enrichment']
  ): number {
    if (scores.length === 0) return 50; // Unknown

    const strategy = this.config.conflict_resolution.strategy;

    if (strategy === 'most_severe') {
      return Math.max(...scores);
    } else if (strategy === 'highest_confidence') {
      // For now, use average (can be refined with confidence weighting)
      return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    } else {
      // majority_vote (default): average
      return Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    }
  }

  /**
   * Determine reputation from threat score
   */
  private determineReputation(
    threatScore: number,
    enrichment: EnrichedIOC['enrichment']
  ): 'clean' | 'suspicious' | 'malicious' | 'unknown' {
    if (threatScore >= 75) return 'malicious';
    if (threatScore >= 50) return 'suspicious';
    if (threatScore >= 25) return 'suspicious';
    if (threatScore > 0) return 'clean';
    return 'unknown';
  }

  /**
   * Calculate confidence based on number of sources
   */
  private calculateConfidence(
    ioc: IOC,
    scoresUsed: number
  ): number {
    if (scoresUsed === 0) return 0;

    // Determine max possible sources for this IOC type
    // Currently: VirusTotal (IP, Domain) + AbuseIPDB (IP)
    const maxPossibleSources = ioc.ioc_type === 'IP' ? 2 : 1;

    // 90% confidence if all possible sources for this type were used successfully
    if (scoresUsed >= maxPossibleSources) return 0.9;

    // 60% if at least one source worked but more were possible
    if (scoresUsed === 1 && maxPossibleSources > 1) return 0.6;

    return 0.5;
  }

  /**
   * Get enrichment from cache
   */
  private async getFromCache(ioc: IOC): Promise<CacheEntry | null> {
    if (!this.redis) return null;

    try {
      const key = `d3:${ioc.ioc_type}:${ioc.ioc_value}`;
      const cached = await this.redis.get(key);

      if (!cached) return null;

      const entry: CacheEntry = JSON.parse(cached);

      // Check if expired
      const age = Date.now() - new Date(entry.cached_at).getTime();
      if (age > entry.ttl * 1000) {
        await this.redis.del(key);
        return null;
      }

      return entry;
    } catch (error) {
      console.error('[D3] Cache get error:', error);
      return null;
    }
  }

  /**
   * Save enrichment to cache
   */
  private async saveToCache(enriched: EnrichedIOC): Promise<void> {
    if (!this.redis) return;

    try {
      const key = `d3:${enriched.ioc_type}:${enriched.ioc_value}`;

      const entry: CacheEntry = {
        ioc_value: enriched.ioc_value,
        ioc_type: enriched.ioc_type,
        enrichment: enriched.enrichment,
        threat_score: enriched.threat_score,
        reputation: enriched.reputation,
        cached_at: enriched.last_enriched,
        ttl: this.config.cache.ttl_seconds
      };

      await this.redis.setex(
        key,
        this.config.cache.ttl_seconds,
        JSON.stringify(entry)
      );
    } catch (error) {
      console.error('[D3] Cache save error:', error);
    }
  }

  /**
   * Generate summary report
   */
  private generateSummary(enrichedIOCs: EnrichedIOC[]) {
    const malicious = enrichedIOCs.filter(i => i.reputation === 'malicious').length;
    const suspicious = enrichedIOCs.filter(i => i.reputation === 'suspicious').length;
    const clean = enrichedIOCs.filter(i => i.reputation === 'clean').length;
    const unknown = enrichedIOCs.filter(i => i.reputation === 'unknown').length;

    const sourcesUsed = new Set<string>();
    enrichedIOCs.forEach(ioc => {
      if (ioc.enrichment.virustotal) sourcesUsed.add('VirusTotal');
      if (ioc.enrichment.abuseipdb) sourcesUsed.add('AbuseIPDB');
    });

    return {
      total_iocs: enrichedIOCs.length,
      malicious_count: malicious,
      suspicious_count: suspicious,
      clean_count: clean,
      unknown_count: unknown,
      sources_used: Array.from(sourcesUsed),
      cache_hits: this.stats.cache_hits,
      api_calls_made: this.stats.vt_calls + this.stats.abuseipdb_calls
    };
  }

  /**
   * Get statistics
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Close connections
   */
  async close() {
    if (this.redis) {
      await this.redis.quit();
    }
  }
}

export default DalionEspionagem;
