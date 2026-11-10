import { SecurityEvent } from '../d2_sentinela/types';

/**
 * Type definitions for Dalion D3 Espionagem
 * Threat Intelligence Enrichment Agent
 */

// ============================================
// Input Types
// ============================================

export interface IOC {
  ioc_type: 'IP' | 'domain' | 'url' | 'hash' | 'email';
  ioc_value: string;
  is_anomaly: boolean;
  context?: Record<string, any>;
  event?: SecurityEvent; // Context event (optional input, required in output)
}

export interface EnrichmentRequest {
  iocs: IOC[];
  sources_priority?: ('VirusTotal' | 'AbuseIPDB' | 'Whois')[];
  analysis_depth?: 'light' | 'medium' | 'deep';
  use_cache?: boolean;
}

// ============================================
// Output Types
// ============================================

export interface EnrichedIOC extends IOC {
  event: SecurityEvent;
  enrichment: {
    virustotal?: VTEnrichment;
    abuseipdb?: AbuseIPDBEnrichment;
    whois?: WhoisEnrichment;
  };
  threat_score: number; // 0-100 (normalized)
  confidence: number; // 0-1
  reputation: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  tags?: string[];
  last_enriched: string; // ISO timestamp
  source?: string;
  context?: Record<string, any>;
  tactical?: any; // D4 TacticalIntel (using any to avoid circular deps if needed)
  psysec?: any; // D7 PsySecAnalysis
}

export interface EnrichmentResult {
  enriched_iocs: EnrichedIOC[];
  summary_report: {
    total_iocs: number;
    malicious_count: number;
    suspicious_count: number;
    clean_count: number;
    unknown_count: number;
    sources_used: string[];
    cache_hits: number;
    api_calls_made: number;
  };
}

// ============================================
// VirusTotal Types
// ============================================

export interface VTEnrichment {
  source: 'VirusTotal';
  reputation_score: number; // -1 (malicious) to +1 (clean)
  last_analysis_stats: {
    malicious: number;
    suspicious: number;
    undetected: number;
    harmless: number;
    timeout: number;
  };
  categories?: string[];
  last_analysis_date?: number; // Unix timestamp
  popularity_ranks?: Record<string, number>;
  total_votes?: {
    harmless: number;
    malicious: number;
  };
}

export interface VTAPIResponse {
  data: {
    id: string;
    type: string;
    attributes: {
      last_analysis_stats: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout: number;
      };
      last_analysis_date: number;
      categories?: Record<string, string>;
      popularity_ranks?: Record<string, { rank: number }>;
      total_votes?: {
        harmless: number;
        malicious: number;
      };
      reputation?: number;
    };
  };
}

// ============================================
// AbuseIPDB Types
// ============================================

export interface AbuseIPDBEnrichment {
  source: 'AbuseIPDB';
  abuse_confidence_score: number; // 0-100
  is_whitelisted: boolean;
  country_code?: string;
  usage_type?: string;
  isp?: string;
  domain?: string;
  total_reports: number;
  num_distinct_users: number;
  last_reported_at?: string;
}

export interface AbuseIPDBAPIResponse {
  data: {
    ipAddress: string;
    isPublic: boolean;
    ipVersion: number;
    isWhitelisted: boolean;
    abuseConfidenceScore: number;
    countryCode: string;
    usageType: string;
    isp: string;
    domain: string;
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt: string;
  };
}

// ============================================
// Whois Types (Future)
// ============================================

export interface WhoisEnrichment {
  source: 'Whois';
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  name_servers?: string[];
  registrant_country?: string;
}

// ============================================
// Cache Types
// ============================================

export interface CacheEntry {
  ioc_value: string;
  ioc_type: string;
  enrichment: EnrichedIOC['enrichment'];
  threat_score: number;
  confidence: number;
  reputation: string;
  tags?: string[];
  source?: string;
  cached_at: string;
  ttl: number; // seconds
}

// ============================================
// Configuration Types
// ============================================

export interface D3Config {
  virustotal: {
    api_key: string;
    rate_limit: {
      max_requests: number; // 4 for free tier
      per_minutes: number; // 1 for free tier
    };
    timeout_ms: number;
  };
  abuseipdb: {
    api_key: string;
    rate_limit: {
      max_requests: number; // 1000 for free tier
      per_day: number; // 1 for free tier
    };
    timeout_ms: number;
  };
  cache: {
    enabled: boolean;
    redis_url: string;
    ttl_seconds: number; // 3600 (1 hour) default
  };
  conflict_resolution: {
    strategy: 'majority_vote' | 'highest_confidence' | 'most_severe';
  };
}

// ============================================
// Error Types
// ============================================

export class EnrichmentError extends Error {
  constructor(
    message: string,
    public source: string,
    public ioc_value: string,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'EnrichmentError';
  }
}

export class RateLimitError extends Error {
  constructor(
    message: string,
    public source: string,
    public retryAfter?: number
  ) {
    super(message);
    this.name = 'RateLimitError';
  }
}

export class APIKeyError extends Error {
  constructor(
    message: string,
    public source: string
  ) {
    super(message);
    this.name = 'APIKeyError';
  }
}
