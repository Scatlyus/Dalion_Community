// ============================================================
// Dalion License System — Type Definitions
// ============================================================

export type Tier = 'community' | 'pro' | 'enterprise';

export type AgentId =
  | 'D1' | 'D2' | 'D3' | 'D4' | 'D5'
  | 'D6' | 'D7' | 'D8' | 'D9' | 'D10'
  | 'D11' | 'D12';

export type Feature =
  | 'suricata_learn'       // --learn flag no ingestor
  | 'suricata_strict'      // --strict flag (compliance gate)
  | 'attack_graph'         // D9 AttackGraph preditivo
  | 'mutation_lab'         // D5 Mutation Lab
  | 'managed_soc'          // Deploy gerenciado
  | 'executive_reports'    // D6 Diplomacia — relatórios exec
  | 'active_response'      // D12 decisão terminal (bite)
  | 'multi_tenant'         // múltiplos clientes/tenants
  | 'sla_support';         // SLA contratual

export interface LicensePayload {
  tier: Tier;
  licensee: string;           // nome da empresa/pessoa
  licenseId: string;          // UUID único
  issuedAt: number;           // Unix timestamp
  expiresAt: number | null;   // null = perpetual (community)
  allowedAgents: AgentId[];
  allowedFeatures: Feature[];
  maxEventsPerSecond: number; // EPS cap
  fingerprint: string;        // HMAC do payload (anti-tamper)
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
