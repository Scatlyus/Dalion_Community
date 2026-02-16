"use strict";
/**
 * Type definitions for Dalion D3 Espionagem
 * Threat Intelligence Enrichment Agent
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.APIKeyError = exports.RateLimitError = exports.EnrichmentError = void 0;
// ============================================
// Error Types
// ============================================
class EnrichmentError extends Error {
    source;
    ioc_value;
    originalError;
    constructor(message, source, ioc_value, originalError) {
        super(message);
        this.source = source;
        this.ioc_value = ioc_value;
        this.originalError = originalError;
        this.name = 'EnrichmentError';
    }
}
exports.EnrichmentError = EnrichmentError;
class RateLimitError extends Error {
    source;
    retryAfter;
    constructor(message, source, retryAfter) {
        super(message);
        this.source = source;
        this.retryAfter = retryAfter;
        this.name = 'RateLimitError';
    }
}
exports.RateLimitError = RateLimitError;
class APIKeyError extends Error {
    source;
    constructor(message, source) {
        super(message);
        this.source = source;
        this.name = 'APIKeyError';
    }
}
exports.APIKeyError = APIKeyError;
