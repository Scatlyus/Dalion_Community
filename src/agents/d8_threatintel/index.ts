import { ThreatIntelSignal, D8Config, IntelSource, IntelHubStatus, ThreatScore } from './types';
import { EnrichedIOC } from '../d3_espionagem/types';

export class DalionThreatIntel {
    private signals: Map<string, ThreatIntelSignal[]> = new Map();
    private config: D8Config;

    constructor(config?: Partial<D8Config>) {
        this.config = {
            enabled_sources: config?.enabled_sources || ['internal_research'],
            min_confidence: config?.min_confidence || 0.6,
            auto_refresh_interval_ms: config?.auto_refresh_interval_ms || 3600000
        };
    }

    /**
     * Agrega múltiplos resultados de enriquecimento para gerar um score consolidado
     */
    public aggregate(sources: EnrichedIOC[]): ThreatScore {
        if (sources.length === 0) {
            return { average_score: 0, weighted_score: 0, confidence: 0, sources_count: 0, timestamp: new Date().toISOString() };
        }

        const first = sources[0];
        if (sources.some(s => s.ioc_type !== first.ioc_type || s.ioc_value !== first.ioc_value)) {
            throw new Error('Cannot aggregate results for different IOCs');
        }

        let totalScore = 0;
        let weightedScore = 0;
        let totalConfidence = 0;

        sources.forEach(s => {
            totalScore += s.threat_score;
            weightedScore += (s.threat_score * s.confidence);
            totalConfidence += s.confidence;
        });

        return {
            average_score: totalScore / sources.length,
            weighted_score: totalConfidence > 0 ? weightedScore / totalConfidence : 0,
            confidence: totalConfidence / sources.length,
            sources_count: sources.length,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Search global feeds for a specific IOC
     */
    public async lookup(iocValue: string): Promise<ThreatIntelSignal[]> {
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
    public ingest(signal: ThreatIntelSignal): void {
        const current = this.signals.get(signal.ioc_value) || [];
        current.push(signal);
        this.signals.set(signal.ioc_value, current);
    }

    public getStatus(): IntelHubStatus {
        let total = 0;
        this.signals.forEach(list => total += list.length);

        return {
            sources_active: this.config.enabled_sources.length,
            total_signals_indexed: total,
            last_update: new Date().toISOString()
        };
    }
}

export default DalionThreatIntel;
