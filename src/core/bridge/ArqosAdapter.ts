import { StrategicDecision } from '../../agents/d12_rottweiler/types';
import { DecisionRecord } from '../../types/omega';

import type { OrchestrationPlan } from './ArqosContracts';

// ── Tipos internos da Bridge ──────────────────────────────────────────────────

export interface DalionEnforcePayload {
    action: string;
    target: string;
    priority: number;
    source: 'dalion';
}

export interface DalionAuditPayload {
    record_id: string;
    policy: string;
    severity: string;
    consensus: boolean;
    timestamp: string;
}

// ── Adaptadores ───────────────────────────────────────────────────────────────

/**
 * Converte uma StrategicDecision do D12 para um OrchestrationPlan do Arqos.
 * Permite que o Arqos execute ações de enforcement (bloqueio, quarentena, etc.)
 * com base nas decisões do pipeline de segurança Dalion.
 */
export function decisionToArqosPlan(decision: StrategicDecision): OrchestrationPlan {
    return {
        id: `dalion-enforce-${Date.now()}`,
        timeout_budget: 5000,
        sequence: [
            {
                tool_name: 'dalion.enforce',
                tool_input: {
                    action: decision.action,
                    target: decision.target,
                    priority: decision.priority,
                    source: 'dalion',
                } satisfies DalionEnforcePayload,
            },
        ],
    };
}

/**
 * Converte um DecisionRecord Ω para um OrchestrationPlan de auditoria.
 * O Arqos registra o evento em log irretratável e notifica stakeholders.
 */
export function omegaToArqosPlan(record: DecisionRecord): OrchestrationPlan {
    return {
        id: `dalion-audit-${record.id}`,
        timeout_budget: 3000,
        sequence: [
            {
                tool_name: 'dalion.audit_log',
                tool_input: {
                    record_id: record.id,
                    policy: record.policy,
                    severity: record.severity,
                    consensus: record.consensus,
                    timestamp: record.timestamp,
                } satisfies DalionAuditPayload,
            },
        ],
    };
}
