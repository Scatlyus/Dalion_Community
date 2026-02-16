"use strict";
// ============================================================
// Dalion License System — Issuer (USO INTERNO CODEARK)
// Gera licenças assinadas para distribuição aos clientes
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.issueLicense = issueLicense;
const crypto_1 = require("crypto");
const signer_1 = require("./signer");
const codec_1 = require("./codec");
const tiers_1 = require("./tiers");
/**
 * Emite uma nova licença assinada.
 * Retorna a string de licença codificada (para enviar ao cliente)
 * e o payload completo (para salvar no backoffice).
 */
function issueLicense(options) {
    const { tier, licensee, validDays } = options;
    const now = Date.now();
    const expiresAt = validDays !== null ? now + validDays * 86_400_000 : null;
    const base = {
        tier,
        licensee,
        licenseId: (0, crypto_1.randomUUID)(),
        issuedAt: now,
        expiresAt,
        allowedAgents: tiers_1.TIER_AGENTS[tier],
        allowedFeatures: tiers_1.TIER_FEATURES[tier],
        maxEventsPerSecond: tiers_1.TIER_EPS_LIMIT[tier], // Agora é Infinity para todos os tiers
    };
    const fingerprint = (0, signer_1.signPayload)(base);
    const payload = { ...base, fingerprint };
    const licenseKey = (0, codec_1.encodeLicense)(payload);
    return { licenseKey, payload };
}
//# sourceMappingURL=issuer.js.map