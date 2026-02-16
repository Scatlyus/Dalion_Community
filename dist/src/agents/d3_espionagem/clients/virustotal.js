"use strict";
/**
 * VirusTotal API Client
 *
 * Free tier limits:
 * - 4 requests per minute
 * - 500 requests per day
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.VirusTotalClient = void 0;
const node_fetch_1 = __importDefault(require("node-fetch"));
const types_1 = require("../types");
class VirusTotalClient {
    apiKey;
    baseUrl = 'https://www.virustotal.com/api/v3';
    timeout;
    constructor(apiKey, timeout = 10000) {
        if (!apiKey || apiKey === 'your_virustotal_key_here') {
            throw new types_1.APIKeyError('Invalid VirusTotal API key', 'VirusTotal');
        }
        this.apiKey = apiKey;
        this.timeout = timeout;
    }
    /**
     * Get domain reputation from VirusTotal
     */
    async getDomainReport(domain) {
        try {
            const url = `${this.baseUrl}/domains/${domain}`;
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            const response = await (0, node_fetch_1.default)(url, {
                headers: {
                    'x-apikey': this.apiKey,
                    'Accept': 'application/json'
                },
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            if (response.status === 429) {
                const retryAfter = response.headers.get('retry-after');
                throw new types_1.RateLimitError('VirusTotal rate limit exceeded', 'VirusTotal', retryAfter ? parseInt(retryAfter) : 60);
            }
            if (response.status === 401) {
                throw new types_1.APIKeyError('Invalid VirusTotal API key', 'VirusTotal');
            }
            if (response.status === 404) {
                // Domain not found in VT database
                return this.createUnknownEnrichment();
            }
            if (!response.ok) {
                throw new Error(`VT API error: ${response.status} ${response.statusText}`);
            }
            const data = await response.json();
            return this.parseVTResponse(data);
        }
        catch (error) {
            if (error instanceof types_1.RateLimitError || error instanceof types_1.APIKeyError) {
                throw error;
            }
            if (error.name === 'AbortError') {
                throw new types_1.EnrichmentError(`VirusTotal request timeout (${this.timeout}ms)`, 'VirusTotal', domain, error);
            }
            throw new types_1.EnrichmentError(`Failed to enrich domain via VirusTotal: ${error.message}`, 'VirusTotal', domain, error);
        }
    }
    /**
     * Get IP reputation from VirusTotal
     */
    async getIPReport(ip) {
        try {
            const url = `${this.baseUrl}/ip_addresses/${ip}`;
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            const response = await (0, node_fetch_1.default)(url, {
                headers: {
                    'x-apikey': this.apiKey,
                    'Accept': 'application/json'
                },
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            if (response.status === 429) {
                const retryAfter = response.headers.get('retry-after');
                throw new types_1.RateLimitError('VirusTotal rate limit exceeded', 'VirusTotal', retryAfter ? parseInt(retryAfter) : 60);
            }
            if (response.status === 401) {
                throw new types_1.APIKeyError('Invalid VirusTotal API key', 'VirusTotal');
            }
            if (response.status === 404) {
                return this.createUnknownEnrichment();
            }
            if (!response.ok) {
                throw new Error(`VT API error: ${response.status} ${response.statusText}`);
            }
            const data = await response.json();
            return this.parseVTResponse(data);
        }
        catch (error) {
            if (error instanceof types_1.RateLimitError || error instanceof types_1.APIKeyError) {
                throw error;
            }
            if (error.name === 'AbortError') {
                throw new types_1.EnrichmentError(`VirusTotal request timeout (${this.timeout}ms)`, 'VirusTotal', ip, error);
            }
            throw new types_1.EnrichmentError(`Failed to enrich IP via VirusTotal: ${error.message}`, 'VirusTotal', ip, error);
        }
    }
    /**
     * Parse VirusTotal API response into enrichment format
     */
    parseVTResponse(data) {
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
            ? Object.fromEntries(Object.entries(attrs.popularity_ranks).map(([k, v]) => [k, v.rank]))
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
    createUnknownEnrichment() {
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
    static normalizeToThreatScore(reputation) {
        return Math.round((1 - reputation) * 50);
    }
}
exports.VirusTotalClient = VirusTotalClient;
