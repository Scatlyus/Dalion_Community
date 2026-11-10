import { AgentTier } from '../../types/omega';

// ── Metadata de cada agente ────────────────────────────────────────────────

export type AgentStatus = 'active' | 'stub' | 'planned';

export interface AgentMeta {
    code: string;       // ex: 'Dn-SEC-INF'
    name: string;       // ex: 'D1 Infantaria'
    tier: AgentTier | 'tactical' | 'strategic' | 'compliance' | 'intel';
    status: AgentStatus;
    path: string;       // caminho relativo a src/agents/
}

// ── Registro canônico dos 12 agentes ─────────────────────────────────────────

export const AGENT_REGISTRY: Record<string, AgentMeta> = {
    D1: { code: 'Dn-SEC-INF', name: 'D1 Infantaria', tier: 'tactical', status: 'active', path: 'd1_infantaria' },
    D2: { code: 'Dn-SEC-SNT', name: 'D2 Sentinela', tier: 'TX.Ω', status: 'active', path: 'd2_sentinela' },
    D3: { code: 'Dn-SEC-ESP', name: 'D3 Espionagem', tier: 'intel', status: 'active', path: 'd3_espionagem' },
    D4: { code: 'Dn-SEC-ICA', name: 'D4 IntelCampo', tier: 'intel', status: 'stub', path: 'd4_intel_campo' },
    D5: { code: 'Dn-SEC-ART', name: 'D5 Artilharia', tier: 'compliance', status: 'active', path: 'd5_artilharia' },
    D6: { code: 'Dn-SEC-DIP', name: 'D6 Diplomacia', tier: 'strategic', status: 'active', path: 'd6_diplomacia' },
    D7: { code: 'Dn-SEC-PSY', name: 'D7 PsySec', tier: 'intel', status: 'stub', path: 'd7_psysec' },
    D8: { code: 'Dn-SEC-THR', name: 'D8 ThreatIntel', tier: 'intel', status: 'stub', path: 'd8_threatintel' },
    D9: { code: 'Dn-SEC-GRA', name: 'D9 AttackGraph', tier: 'strategic', status: 'active', path: 'd9_attackgraph' },
    D10: { code: 'Dn-SEC-ETH', name: 'D10 Ethos', tier: 'TE.Ω', status: 'active', path: 'd10_ethos' },
    D11: { code: 'Dn-SEC-AFT', name: 'D11 AfterAction', tier: 'strategic', status: 'stub', path: 'd11_afteraction' },
    D12: { code: 'Dn-SEC-ROT', name: 'D12 Rottweiler', tier: 'TA.Ω', status: 'active', path: 'd12_rottweiler' },
} as const;

// ── Helpers ───────────────────────────────────────────────────────────────────

export const getActiveAgents = (): AgentMeta[] =>
    Object.values(AGENT_REGISTRY).filter(a => a.status === 'active');

export const getStubAgents = (): AgentMeta[] =>
    Object.values(AGENT_REGISTRY).filter(a => a.status === 'stub');
