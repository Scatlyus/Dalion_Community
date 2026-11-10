import { DetectionResult } from '../../agents/d2_sentinela/types';
import { EnrichedIOC } from '../../agents/d3_espionagem/types';
import { ClassificationResult } from '../../agents/d10_ethos/types';
import { StrategicDecision } from '../../agents/d12_rottweiler/types';
import { DecisionRecord } from '../../types/omega';

// ---------------------------------------------------------------------------
// ArqosToolResult — payload retornado pelo ToolOrchestrator do Arqos Engine
// ---------------------------------------------------------------------------
export interface ArqosToolResult {
    tool: string;
    ok: boolean;
    value?: unknown;
    error?: { code: string; message: string };
}

// ---------------------------------------------------------------------------
// DalionEvent — union discriminada de todos os eventos do pipeline
// ---------------------------------------------------------------------------
export type DalionEvent =
    // ── Agentes de Detecção ──────────────────────────────────────────────
    | { type: 'D2_DETECTION'; payload: DetectionResult }
    | { type: 'D3_ENRICHMENT'; payload: EnrichedIOC }
    | { type: 'D3_ERROR'; payload: { source_ip: string; error: string } }
    | { type: 'D10_CLASSIFICATION'; payload: ClassificationResult }
    | { type: 'D10_ERROR'; payload: { ioc_value: string; error: string } }
    // ── Decisão Estratégica ───────────────────────────────────────────────
    | { type: 'D12_DECISION'; payload: StrategicDecision }
    // ── Consenso Soberano (Ω) ────────────────────────────────────────────
    | { type: 'OMEGA_CONSENSUS'; payload: DecisionRecord }
    // ── Arqos Engine ─────────────────────────────────────────────────────
    | { type: 'ARQOS_TOOL_RESULT'; payload: ArqosToolResult };

// Helper: extrai o payload de um tipo de evento específico
export type EventPayload<T extends DalionEvent['type']> = Extract<
    DalionEvent,
    { type: T }
>['payload'];
