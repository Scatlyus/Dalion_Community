/**
 * VirusTotal API Client
 * 
 * Free tier limits:
 * - 4 requests per minute
 * - 500 requests per day
 */

import fetch from 'node-fetch';
import { 
  VTEnrichment, 
  VTAPIResponse, 
  EnrichmentError, 
  RateLimitError,
  APIKeyError 
} from '../types';

export class VirusTotalClient {
  private apiKey: string;
  private baseUrl = 'https://www.virustotal.com/api/v3';
  private timeout: number;

  constructor(apiKey: string, timeout: number = 10000) {
    if (!apiKey || apiKey === 'your_virustotal_key_here') {
      throw new APIKeyError('Invalid VirusTotal API key', 'VirusTotal');
    }
    this.apiKey = apiKey;
    this.timeout = timeout;
  }

  /**
   * Get domain reputation from VirusTotal
   */
  async getDomainReport(domain: string): Promise<VTEnrichment> {
    try {
      const url = `${this.baseUrl}/domains/${domain}`;
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(url, {
        headers: {
          'x-apikey': this.apiKey,
          'Accept': 'application/json'
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.status === 429) {
        const retryAfter = response.headers.get('retry-after');
        throw new RateLimitError(
          'VirusTotal rate limit exceeded',
          'VirusTotal',
          retryAfter ? parseInt(retryAfter) : 60
        );
      }

      if (response.status === 401) {
        throw new APIKeyError('Invalid VirusTotal API key', 'VirusTotal');
      }

      if (response.status === 404) {
        // Domain not found in VT database
        return this.createUnknownEnrichment();
      }

      if (!response.ok) {
        throw new Error(`VT API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as VTAPIResponse;
      return this.parseVTResponse(data);

    } catch (error) {
      if (error instanceof RateLimitError || error instanceof APIKeyError) {
        throw error;
      }

      const cause = error instanceof Error ? error : new Error(String(error));
      if (cause.name === 'AbortError') {
        throw new EnrichmentError(
          `VirusTotal request timeout (${this.timeout}ms)`,
          'VirusTotal',
          domain,
          cause
        );
      }

      throw new EnrichmentError(
        `Failed to enrich domain via VirusTotal: ${cause.message}`,
        'VirusTotal',
        domain,
        cause
      );
    }
  }

  /**
   * Get IP reputation from VirusTotal
   */
  async getIPReport(ip: string): Promise<VTEnrichment> {
    try {
      const url = `${this.baseUrl}/ip_addresses/${ip}`;
      
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(url, {
        headers: {
          'x-apikey': this.apiKey,
          'Accept': 'application/json'
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.status === 429) {
        const retryAfter = response.headers.get('retry-after');
        throw new RateLimitError(
          'VirusTotal rate limit exceeded',
          'VirusTotal',
          retryAfter ? parseInt(retryAfter) : 60
        );
      }

      if (response.status === 401) {
        throw new APIKeyError('Invalid VirusTotal API key', 'VirusTotal');
      }

      if (response.status === 404) {
        return this.createUnknownEnrichment();
      }

      if (!response.ok) {
        throw new Error(`VT API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as VTAPIResponse;
      return this.parseVTResponse(data);

    } catch (error) {
      if (error instanceof RateLimitError || error instanceof APIKeyError) {
        throw error;
      }

      const cause = error instanceof Error ? error : new Error(String(error));
      if (cause.name === 'AbortError') {
        throw new EnrichmentError(
          `VirusTotal request timeout (${this.timeout}ms)`,
          'VirusTotal',
          ip,
          cause
        );
      }

      throw new EnrichmentError(
        `Failed to enrich IP via VirusTotal: ${cause.message}`,
        'VirusTotal',
        ip,
        cause
      );
    }
  }

  /**
   * Parse VirusTotal API response into enrichment format
   */
  private parseVTResponse(data: VTAPIResponse): VTEnrichment {
    const attrs = data.data.attributes;
    const stats = attrs.last_analysis_stats;

    // Calculate reputation score (-1 to +1)
    const total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;
    const bad = stats.malicious + (stats.suspicious * 0.5);
    const reputation_score = total > 0 ? 1 - (2 * bad / total) : 0;

    // Extract categories
    const categories = attrs.categories 
      ? Object.values(attrs.categories)
      : undefined;

    // Extract popularity ranks
    const popularity_ranks = attrs.popularity_ranks
      ? Object.fromEntries(
          Object.entries(attrs.popularity_ranks).map(([k, v]) => [k, v.rank])
        )
      : undefined;

    return {
      source: 'VirusTotal',
      reputation_score,
      last_analysis_stats: stats,
      categories,
      last_analysis_date: attrs.last_analysis_date,
      popularity_ranks,
      total_votes: attrs.total_votes
    };
  }

  /**
   * Create enrichment result for unknown/not-found items
   */
  private createUnknownEnrichment(): VTEnrichment {
    return {
      source: 'VirusTotal',
      reputation_score: 0,
      last_analysis_stats: {
        malicious: 0,
        suspicious: 0,
        undetected: 0,
        harmless: 0,
        timeout: 0
      }
    };
  }

  /**
   * Normalize reputation score to 0-100 threat score
   * -1 (malicious) → 100
   *  0 (unknown)   → 50
   * +1 (clean)     → 0
   */
  static normalizeToThreatScore(reputation: number): number {
    return Math.round((1 - reputation) * 50);
  }
}
