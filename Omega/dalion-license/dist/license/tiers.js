"use strict";
// ============================================================
// Dalion License System — Tier Definitions
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.AGENT_NAMES = exports.EPS_WARNING_THRESHOLD = exports.TIER_EPS_LIMIT = exports.TIER_FEATURES = exports.TIER_AGENTS = void 0;
exports.TIER_AGENTS = {
    community: ['D1', 'D2', 'D10', 'D11'],
    pro: ['D1', 'D2', 'D3', 'D4', 'D7', 'D8', 'D10', 'D11'],
    enterprise: ['D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9', 'D10', 'D11', 'D12'],
};
exports.TIER_FEATURES = {
    community: [],
    pro: ['suricata_strict', 'executive_reports'],
    enterprise: [
        'suricata_learn',
        'suricata_strict',
        'attack_graph',
        'mutation_lab',
        'managed_soc',
        'executive_reports',
        'active_response',
        'multi_tenant',
        'sla_support',
    ],
};
// EPS ilimitado para todos os tiers
// Diferenciação por agentes e features, não por volume
exports.TIER_EPS_LIMIT = {
    community: Infinity, // Ilimitado
    pro: Infinity, // Ilimitado
    enterprise: Infinity, // Ilimitado
};
// Soft warning threshold (log apenas, não bloqueia)
// Sugere escalar infraestrutura se ultrapassar
exports.EPS_WARNING_THRESHOLD = 5_000;
exports.AGENT_NAMES = {
    D1: 'Infantaria (Dn-SEC-INF)',
    D2: 'Sentinela (Dn-SEC-SNT)',
    D3: 'Espionagem (Dn-SEC-ESP)',
    D4: 'IntelCampo (Dn-SEC-ICA)',
    D5: 'Artilharia (Dn-SEC-ART)',
    D6: 'Diplomacia (Dn-SEC-DIP)',
    D7: 'PsySec (Dn-SEC-PSY)',
    D8: 'ThreatIntel (Dn-SEC-THR)',
    D9: 'AttackGraph (Dn-SEC-GRA)',
    D10: 'Ethos (Dn-SEC-ETH)',
    D11: 'AfterAction (Dn-SEC-AFT)',
    D12: 'Rottweiler (Dn-SEC-ROT)',
};
//# sourceMappingURL=tiers.js.map