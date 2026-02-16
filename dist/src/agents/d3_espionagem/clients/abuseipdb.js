"use strict";
/**
 * AbuseIPDB API Client
 *
 * Free tier limits:
 * - 1,000 requests per day
 * - Max 100 requests per day per IP
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AbuseIPDBClient = void 0;
const node_fetch_1 = __importDefault(require("node-fetch"));
const types_1 = require("../types");
class AbuseIPDBClient {
    apiKey;
    baseUrl = 'https://api.abuseipdb.com/api/v2';
    timeout;
    constructor(apiKey, timeout = 10000) {
        if (!apiKey || apiKey === 'your_abuseipdb_key_here') {
            throw new types_1.APIKeyError('Invalid AbuseIPDB API key', 'AbuseIPDB');
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
    async checkIP(ip, maxAgeInDays = 90, verbose = false) {
        try {
            const url = new URL(`${this.baseUrl}/check`);
            url.searchParams.append('ipAddress', ip);
            url.searchParams.append('maxAgeInDays', maxAgeInDays.toString());
            url.searchParams.append('verbose', verbose.toString());
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            const response = await (0, node_fetch_1.default)(url.toString(), {
                headers: {
                    'Key': this.apiKey,
                    'Accept': 'application/json'
                },
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            if (response.status === 429) {
                throw new types_1.RateLimitError('AbuseIPDB rate limit exceeded', 'AbuseIPDB', 86400 // 24 hours
                );
            }
            if (response.status === 401 || response.status === 403) {
                throw new types_1.APIKeyError('Invalid AbuseIPDB API key', 'AbuseIPDB');
            }
            if (response.status === 422) {
                // Invalid IP format
                throw new types_1.EnrichmentError(`Invalid IP address format: ${ip}`, 'AbuseIPDB', ip);
            }
            if (!response.ok) {
                throw new Error(`AbuseIPDB API error: ${response.status} ${response.statusText}`);
            }
            const data = await response.json();
            return this.parseAbuseIPDBResponse(data);
        }
        catch (error) {
            if (error instanceof types_1.RateLimitError || error instanceof types_1.APIKeyError) {
                throw error;
            }
            if (error.name === 'AbortError') {
                throw new types_1.EnrichmentError(`AbuseIPDB request timeout (${this.timeout}ms)`, 'AbuseIPDB', ip, error);
            }
            throw new types_1.EnrichmentError(`Failed to check IP via AbuseIPDB: ${error.message}`, 'AbuseIPDB', ip, error);
        }
    }
    /**
     * Parse AbuseIPDB API response into enrichment format
     */
    parseAbuseIPDBResponse(data) {
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
    static isIPMalicious(score) {
        return score >= 50;
    }
    /**
     * Normalize AbuseIPDB score (0-100) to threat score (0-100)
     * This is already normalized, but we keep the method for consistency
     */
    static normalizeToThreatScore(abuseScore) {
        return abuseScore;
    }
}
exports.AbuseIPDBClient = AbuseIPDBClient;
