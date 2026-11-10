import { DalionSentinela } from '../../agents/d2_sentinela';
import { DalionEspionagem } from '../../agents/d3_espionagem';
import { DalionEthos } from '../../agents/d10_ethos';
import { DalionRottweiler } from '../../agents/d12_rottweiler';
import { SovereignTriad } from '../triad/SovereignTriad';
import { DalionEventBus } from '../bus/DalionEventBus';
import { SecurityEvent } from '../../agents/d2_sentinela/types';
import { EnrichedIOC } from '../../agents/d3_espionagem/types';
import { StrategicDecision } from '../../agents/d12_rottweiler/types';
import { EpistemicSignal } from '../../types/omega';
import { IoCExtractor } from './IoCExtractor';
import { DecisionEngine } from './DecisionEngine';
import { DalionStateContext } from './DalionStateContext';

// ── Configuração ──────────────────────────────────────────────────────────────

export interface OrchestratorConfig {
    /**
     * Score mínimo do D2 para acionar o consenso Ω (SovereignTriad).
     * Configurável para evitar threshold hardcoded.
     * @default 80
     */
    omegaThreshold: number;
}

const DEFAULT_CONFIG: OrchestratorConfig = {
    omegaThreshold: 80,
};

// ── Resultado do pipeline ─────────────────────────────────────────────────────

export interface PipelineResult {
    decision: StrategicDecision;
    d2_score: number;
    d3_ioc: EnrichedIOC;
    omega_triggered: boolean;
    errors: string[];
}

// ── Orquestrador Central ─────────────────────────────────────────────────────

/**
 * DalionOrchestrator — Maestro do pipeline de segurança.
 *
 * Fluxo: SecurityEvent → D2 → D3 → D10 → D12 → StrategicDecision
 *
 * Error boundaries: cada etapa é isolada em try/catch. Se D3 ou D10 falharem,
 * o pipeline continua com dados parciais e publica o evento de erro no bus.
 * Isso garante que uma API externa instável não paralise toda a defesa.
 */
export class DalionOrchestrator {
    private config: OrchestratorConfig;
    private readonly extractor: IoCExtractor;
    private readonly engine: DecisionEngine;

    constructor(
        private readonly d2: DalionSentinela,
        private readonly d3: DalionEspionagem,
        private readonly d10: DalionEthos,
        private readonly d12: DalionRottweiler,
        private readonly triad: SovereignTriad,
        private readonly bus: DalionEventBus,
        config?: Partial<OrchestratorConfig>
    ) {
        this.config = { ...DEFAULT_CONFIG, ...config };
        this.extractor = new IoCExtractor();
        this.engine = new DecisionEngine();
    }

    /**
     * Processa um SecurityEvent pelo pipeline completo.
     * Retorna a decisão estratégica e metadados de execução.
     */
    async process(event: SecurityEvent): Promise<PipelineResult> {
        const errors: string[] = [];

        // ── ETAPA 1: D2 Sentinela — Detecção local ───────────────────────────
        const d2Result = await this.d2.analyze(event);
        this.bus.publish({ type: 'D2_DETECTION', payload: d2Result });

        // ── ETAPA 2: D3 Espionagem — Enriquecimento multi-dimensional paralelo ─
        let consolidatedD3: EnrichedIOC;
        try {
            const iocs = this.extractor.extractFromEvent(event);

            // Marcar IoCs com o status de anomalia do D2 (especialmente IPs)
            iocs.forEach(ioc => {
                if (ioc.ioc_type === 'IP' && ioc.ioc_value === event.source_ip) {
                    ioc.is_anomaly = d2Result.anomaly;
                }
            });

            const enrichmentPromises = iocs.map(async (ioc) => {
                try {
                    const result = await this.d3.enrich({
                        iocs: [ioc],
                        use_cache: true
                    });
                    return result.enriched_iocs[0];
                } catch (err) {
                    const errorMsg = err instanceof Error ? err.message : String(err);
                    errors.push(`D3_ERROR (${ioc.ioc_type}:${ioc.ioc_value}): ${errorMsg}`);
                    this.bus.publish({ type: 'D3_ERROR', payload: { source_ip: event.source_ip, error: errorMsg } });
                    return this.buildFallbackIOC(event, d2Result.anomaly, ioc.ioc_type, ioc.ioc_value);
                }
            });

            const enrichedResults = await Promise.all(enrichmentPromises);

            // Consolidar múltiplos resultados em um único contexto mestre
            consolidatedD3 = this.engine.consolidate(enrichedResults, event);

            this.bus.publish({ type: 'D3_ENRICHMENT', payload: consolidatedD3 });
        } catch (err) {
            // Error boundary global da Etapa 2
            const errorMsg = err instanceof Error ? err.message : String(err);
            errors.push(`D3_CRITICAL_ERROR: ${errorMsg}`);
            this.bus.publish({ type: 'D3_ERROR', payload: { source_ip: event.source_ip, error: errorMsg } });
            consolidatedD3 = this.buildFallbackIOC(event, d2Result.anomaly, 'IP', event.source_ip);
        }

        // ── ETAPA 3: D10 Ethos — Classificação taxonômica ────────────────────
        let d10Result;
        try {
            d10Result = await this.d10.classify(consolidatedD3);
            this.bus.publish({ type: 'D10_CLASSIFICATION', payload: d10Result });
        } catch (err) {
            // Error boundary: D10 falhou — D12 decide sem classificação taxonômica
            const errorMsg = err instanceof Error ? err.message : String(err);
            errors.push(`D10_ERROR: ${errorMsg}`);
            this.bus.publish({ type: 'D10_ERROR', payload: { ioc_value: consolidatedD3.ioc_value, error: errorMsg } });
            d10Result = undefined;
        }

        // ── ETAPA 4: D12 Rottweiler — Decisão Estratégica ────────────────────
        const stateContext = DalionStateContext.getInstance();
        const hostContext = stateContext.getHostContext(event.source_ip);

        const decision = this.d12.decide(d2Result, consolidatedD3, d10Result, hostContext);
        this.bus.publish({ type: 'D12_DECISION', payload: decision });

        // Atualizar estado global (AX-DLN-004)
        stateContext.updateHostState(event, consolidatedD3.threat_score || 0);

        // ── ETAPA 5: SovereignTriad Ω — Consenso soberano (score alto) ───────
        const omegaTriggered = d2Result.anomaly_score >= this.config.omegaThreshold;
        if (omegaTriggered) {
            await this.activateOmega(event, d2Result.anomaly_score, d10Result?.confidence ?? 0.5);
        }

        return {
            decision,
            d2_score: d2Result.anomaly_score,
            d3_ioc: consolidatedD3,
            omega_triggered: omegaTriggered,
            errors,
        };
    }

    // ── Helpers privados ──────────────────────────────────────────────────────

    private async activateOmega(
        event: SecurityEvent,
        d2Score: number,
        d10Confidence: number
    ): Promise<void> {
        const now = new Date().toISOString();
        const evidence = { target_ip: event.source_ip, event_id: event.event_id };

        const txSignal: EpistemicSignal = {
            agentId: 'D2',
            tier: 'TX.Ω',
            timestamp: now,
            confidence: d2Score / 100,
            entropy: 0,
            evidence,
        };

        const teSignal: EpistemicSignal = {
            agentId: 'D10',
            tier: 'TE.Ω',
            timestamp: now,
            confidence: d10Confidence,
            entropy: 0,
            evidence,
        };

        await this.triad.registerSignal(txSignal);
        await this.triad.registerSignal(teSignal);
    }

    private buildFallbackIOC(
        event: SecurityEvent,
        isAnomaly: boolean,
        iocType: 'IP' | 'domain' | 'url' | 'hash' | 'email' = 'IP',
        iocValue?: string
    ): EnrichedIOC {
        return {
            ioc_type: iocType,
            ioc_value: iocValue || event.source_ip,
            is_anomaly: isAnomaly,
            event,
            enrichment: {},
            threat_score: isAnomaly ? 50 : 10,
            confidence: 0,
            reputation: 'unknown',
            last_enriched: new Date().toISOString(),
        };
    }
}
