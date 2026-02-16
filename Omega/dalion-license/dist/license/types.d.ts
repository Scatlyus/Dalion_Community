export type Tier = 'community' | 'pro' | 'enterprise';
export type AgentId = 'D1' | 'D2' | 'D3' | 'D4' | 'D5' | 'D6' | 'D7' | 'D8' | 'D9' | 'D10' | 'D11' | 'D12';
export type Feature = 'suricata_learn' | 'suricata_strict' | 'attack_graph' | 'mutation_lab' | 'managed_soc' | 'executive_reports' | 'active_response' | 'multi_tenant' | 'sla_support';
export interface LicensePayload {
    tier: Tier;
    licensee: string;
    licenseId: string;
    issuedAt: number;
    expiresAt: number | null;
    allowedAgents: AgentId[];
    allowedFeatures: Feature[];
    maxEventsPerSecond: number;
    fingerprint: string;
}
export interface ValidationResult {
    valid: boolean;
    tier: Tier;
    licensee: string;
    expiresAt: number | null;
    daysRemaining: number | null;
    allowedAgents: AgentId[];
    allowedFeatures: Feature[];
    maxEventsPerSecond: number;
    warnings: string[];
    errors: string[];
}
//# sourceMappingURL=types.d.ts.map