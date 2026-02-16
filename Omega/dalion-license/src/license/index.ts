// ============================================================
// Dalion License System — Public API
// ============================================================

// Singleton manager (uso nos agentes)
export { licenseManager, LicenseManager } from './manager';

// Tipos
export type {
  Tier,
  AgentId,
  Feature,
  LicensePayload,
  ValidationResult,
} from './types';

// Tier metadata (útil para UI/docs)
export { TIER_AGENTS, TIER_FEATURES, TIER_EPS_LIMIT, EPS_WARNING_THRESHOLD, AGENT_NAMES } from './tiers';

// Codec (encode/decode de license keys)
export { encodeLicense, decodeLicense } from './codec';

// Validator standalone
export { validateLicense, assertAgentAllowed, assertFeatureAllowed, checkEPSWarning } from './validator';

// Issuer — SOMENTE para uso interno da CodeArk
// Não inclua este export no bundle do cliente
export { issueLicense } from './issuer';
