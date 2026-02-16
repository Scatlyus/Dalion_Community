/**
 * AbuseIPDB API Client
 * 
 * Free tier limits:
 * - 1,000 requests per day
 * - Max 100 requests per day per IP
 */

import fetch from 'node-fetch';
import { 
  AbuseIPDBEnrichment, 
  AbuseIPDBAPIResponse, 
  EnrichmentError,
  RateLimitError,
  APIKeyError 
} from '../types';

export class AbuseIPDBClient {
  private apiKey: string;
  private baseUrl = 'https://api.abuseipdb.com/api/v2';
  private timeout: number;

  constructor(apiKey: string, timeout: number = 10000) {
    if (!apiKey || apiKey === 'your_abuseipdb_key_here') {
      throw new APIKeyError('Invalid AbuseIPDB API key', 'AbuseIPDB');
    }
    this.apiKey = apiKey;
    this.timeout = timeout;
  }

  /**
   * Check IP reputation on AbuseIPDB
   * 
   * @param ip - IP address to check
   * @param maxAgeInDays - Consider reports from last N days (default: 90)
   * @param verbose - Include detailed report data
   */
  async checkIP(
    ip: string, 
    maxAgeInDays: number = 90,
    verbose: boolean = false
  ): Promise<AbuseIPDBEnrichment> {
    try {
      const url = new URL(`${this.baseUrl}/check`);
      url.searchParams.append('ipAddress', ip);
      url.searchParams.append('maxAgeInDays', maxAgeInDays.toString());
      url.searchParams.append('verbose', verbose.toString());

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(url.toString(), {
        headers: {
          'Key': this.apiKey,
          'Accept': 'application/json'
        },
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (response.status === 429) {
        throw new RateLimitError(
          'AbuseIPDB rate limit exceeded',
          'AbuseIPDB',
          86400 // 24 hours
        );
      }

      if (response.status === 401 || response.status === 403) {
        throw new APIKeyError('Invalid AbuseIPDB API key', 'AbuseIPDB');
      }

      if (response.status === 422) {
        // Invalid IP format
        throw new EnrichmentError(
          `Invalid IP address format: ${ip}`,
          'AbuseIPDB',
          ip
        );
      }

      if (!response.ok) {
        throw new Error(`AbuseIPDB API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json() as AbuseIPDBAPIResponse;
      return this.parseAbuseIPDBResponse(data);

    } catch (error) {
      if (error instanceof RateLimitError || error instanceof APIKeyError) {
        throw error;
      }

      if (error.name === 'AbortError') {
        throw new EnrichmentError(
          `AbuseIPDB request timeout (${this.timeout}ms)`,
          'AbuseIPDB',
          ip,
          error
        );
      }

      throw new EnrichmentError(
        `Failed to check IP via AbuseIPDB: ${error.message}`,
        'AbuseIPDB',
        ip,
        error
      );
    }
  }

  /**
   * Parse AbuseIPDB API response into enrichment format
   */
  private parseAbuseIPDBResponse(data: AbuseIPDBAPIResponse): AbuseIPDBEnrichment {
    const ipData = data.data;

    return {
      source: 'AbuseIPDB',
      abuse_confidence_score: ipData.abuseConfidenceScore,
      is_whitelisted: ipData.isWhitelisted,
      country_code: ipData.countryCode,
      usage_type: ipData.usageType,
      isp: ipData.isp,
      domain: ipData.domain,
      total_reports: ipData.totalReports,
      num_distinct_users: ipData.numDistinctUsers,
      last_reported_at: ipData.lastReportedAt
    };
  }

  /**
   * Determine if IP is considered malicious based on confidence score
   * 
   * AbuseIPDB scoring:
   * 0-25: Low risk
   * 26-50: Medium risk
   * 51-75: High risk
   * 76-100: Critical risk
   */
  static isIPMalicious(score: number): boolean {
    return score >= 50;
  }

  /**
   * Normalize AbuseIPDB score (0-100) to threat score (0-100)
   * This is already normalized, but we keep the method for consistency
   */
  static normalizeToThreatScore(abuseScore: number): number {
    return abuseScore;
  }
}
