export { licenseManager, LicenseManager } from './manager';
export type { Tier, AgentId, Feature, LicensePayload, ValidationResult, } from './types';
export { TIER_AGENTS, TIER_FEATURES, TIER_EPS_LIMIT, EPS_WARNING_THRESHOLD, AGENT_NAMES } from './tiers';
export { encodeLicense, decodeLicense } from './codec';
export { validateLicense, assertAgentAllowed, assertFeatureAllowed, checkEPSWarning } from './validator';
export { issueLicense } from './issuer';
//# sourceMappingURL=index.d.ts.map