"use strict";
// ============================================================
// Dalion License System — Public API
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.issueLicense = exports.checkEPSWarning = exports.assertFeatureAllowed = exports.assertAgentAllowed = exports.validateLicense = exports.decodeLicense = exports.encodeLicense = exports.AGENT_NAMES = exports.EPS_WARNING_THRESHOLD = exports.TIER_EPS_LIMIT = exports.TIER_FEATURES = exports.TIER_AGENTS = exports.LicenseManager = exports.licenseManager = void 0;
// Singleton manager (uso nos agentes)
var manager_1 = require("./manager");
Object.defineProperty(exports, "licenseManager", { enumerable: true, get: function () { return manager_1.licenseManager; } });
Object.defineProperty(exports, "LicenseManager", { enumerable: true, get: function () { return manager_1.LicenseManager; } });
// Tier metadata (útil para UI/docs)
var tiers_1 = require("./tiers");
Object.defineProperty(exports, "TIER_AGENTS", { enumerable: true, get: function () { return tiers_1.TIER_AGENTS; } });
Object.defineProperty(exports, "TIER_FEATURES", { enumerable: true, get: function () { return tiers_1.TIER_FEATURES; } });
Object.defineProperty(exports, "TIER_EPS_LIMIT", { enumerable: true, get: function () { return tiers_1.TIER_EPS_LIMIT; } });
Object.defineProperty(exports, "EPS_WARNING_THRESHOLD", { enumerable: true, get: function () { return tiers_1.EPS_WARNING_THRESHOLD; } });
Object.defineProperty(exports, "AGENT_NAMES", { enumerable: true, get: function () { return tiers_1.AGENT_NAMES; } });
// Codec (encode/decode de license keys)
var codec_1 = require("./codec");
Object.defineProperty(exports, "encodeLicense", { enumerable: true, get: function () { return codec_1.encodeLicense; } });
Object.defineProperty(exports, "decodeLicense", { enumerable: true, get: function () { return codec_1.decodeLicense; } });
// Validator standalone
var validator_1 = require("./validator");
Object.defineProperty(exports, "validateLicense", { enumerable: true, get: function () { return validator_1.validateLicense; } });
Object.defineProperty(exports, "assertAgentAllowed", { enumerable: true, get: function () { return validator_1.assertAgentAllowed; } });
Object.defineProperty(exports, "assertFeatureAllowed", { enumerable: true, get: function () { return validator_1.assertFeatureAllowed; } });
Object.defineProperty(exports, "checkEPSWarning", { enumerable: true, get: function () { return validator_1.checkEPSWarning; } });
// Issuer — SOMENTE para uso interno da CodeArk
// Não inclua este export no bundle do cliente
var issuer_1 = require("./issuer");
Object.defineProperty(exports, "issueLicense", { enumerable: true, get: function () { return issuer_1.issueLicense; } });
//# sourceMappingURL=index.js.map