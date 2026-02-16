"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DalionThreatIntel = void 0;
class DalionThreatIntel {
    signals = new Map();
    config;
    constructor(config) {
        this.config = {
            enabled_sources: config?.enabled_sources || ['internal_research'],
            min_confidence: config?.min_confidence || 0.6,
            auto_refresh_interval_ms: config?.auto_refresh_interval_ms || 3600000
        };
    }
    /**
     * Search global feeds for a specific IOC
     */
    async lookup(iocValue) {
        console.log(`[D8 ThreatIntel] Searching global feeds for ${iocValue}...`);
        // Simulação de busca em múltiplos adaptadores
        const found = this.signals.get(iocValue) || [];
        // Adiciona um sinal mock para demonstrar a inteligência de D8
        if (iocValue.includes('malicious-pdf-link.com')) {
            found.push({
                source: 'internal_research',
                ioc_value: iocValue,
                ioc_type: 'domain',
                confidence: 0.95,
                threat_level: 'critical',
                tags: ['embedded_pdf_phishing', 'high_variance_url'],
                recommended_score_boost: 60,
                last_seen: new Date().toISOString()
            });
        }
        // Persist signals back to map if not already there (ensures mock or discovery is indexed)
        if (!this.signals.has(iocValue)) {
            this.signals.set(iocValue, found);
        }
        return found.filter(s => s.confidence >= this.config.min_confidence);
    }
    /**
     * Ingest a new signal into the hub (from external adapters)
     */
    ingest(signal) {
        const current = this.signals.get(signal.ioc_value) || [];
        current.push(signal);
        this.signals.set(signal.ioc_value, current);
    }
    getStatus() {
        let total = 0;
        this.signals.forEach(list => total += list.length);
        return {
            sources_active: this.config.enabled_sources.length,
            total_signals_indexed: total,
            last_update: new Date().toISOString()
        };
    }
}
exports.DalionThreatIntel = DalionThreatIntel;
exports.default = DalionThreatIntel;
