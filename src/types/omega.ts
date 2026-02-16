export type AgentTier = 'TX.Ω' | 'TE.Ω' | 'TA.Ω';

export interface EpistemicSignal {
    agentId: string;
    tier: AgentTier;
    timestamp: string;
    confidence: number;
    entropy: number;
    evidence: any;
}

export interface DecisionRecord {
    id: string;
    policy: string;
    action: string;
    target: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    consensus: boolean;
    timestamp: string;
}
