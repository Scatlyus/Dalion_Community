"use strict";
// ============================================================
// Dalion License System — Encoder / Decoder
// Formato: base64(JSON(LicensePayload))
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.encodeLicense = encodeLicense;
exports.decodeLicense = decodeLicense;
const LICENSE_PREFIX = 'DLICV1:';
/**
 * Encoda um payload assinado para uma string de licença portável.
 * Exemplo: DLICV1:eyJ0aWVyIjoicHJvIiwi...
 */
function encodeLicense(payload) {
    const json = JSON.stringify(payload);
    const b64 = Buffer.from(json, 'utf8').toString('base64');
    return `${LICENSE_PREFIX}${b64}`;
}
/**
 * Decoda uma string de licença de volta para o payload.
 * Lança erro se o formato for inválido.
 */
function decodeLicense(licenseString) {
    const trimmed = licenseString.trim();
    if (!trimmed.startsWith(LICENSE_PREFIX)) {
        throw new Error(`LICENSE_FORMAT_ERROR: Licença deve começar com "${LICENSE_PREFIX}"`);
    }
    const b64 = trimmed.slice(LICENSE_PREFIX.length);
    let json;
    try {
        json = Buffer.from(b64, 'base64').toString('utf8');
    }
    catch {
        throw new Error('LICENSE_DECODE_ERROR: Falha ao decodificar base64.');
    }
    let payload;
    try {
        payload = JSON.parse(json);
    }
    catch {
        throw new Error('LICENSE_PARSE_ERROR: JSON inválido no payload da licença.');
    }
    // Validação estrutural mínima
    const required = ['tier', 'licensee', 'licenseId', 'issuedAt', 'expiresAt',
        'allowedAgents', 'allowedFeatures', 'maxEventsPerSecond', 'fingerprint'];
    for (const field of required) {
        if (!(field in payload)) {
            throw new Error(`LICENSE_MISSING_FIELD: Campo "${field}" ausente na licença.`);
        }
    }
    return payload;
}
//# sourceMappingURL=codec.js.map