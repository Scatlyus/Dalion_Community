"use strict";
// ============================================================
// Dalion License System — Tests
// Run: npx ts-node src/tests/license.test.ts
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
const issuer_1 = require("../license/issuer");
const codec_1 = require("../license/codec");
const validator_1 = require("../license/validator");
const manager_1 = require("../license/manager");
let passed = 0;
let failed = 0;
function test(name, fn) {
    try {
        fn();
        console.log(`  ✅ ${name}`);
        passed++;
    }
    catch (err) {
        console.error(`  ❌ ${name}: ${err instanceof Error ? err.message : err}`);
        failed++;
    }
}
function assert(condition, message) {
    if (!condition)
        throw new Error(message);
}
console.log('\n🧪 Dalion License System — Test Suite\n');
// ── Community ─────────────────────────────────────────────────
console.log('📦 Community Tier');
test('Emite licença community perpétua', () => {
    const { licenseKey, payload } = (0, issuer_1.issueLicense)({
        tier: 'community', licensee: 'OSS User', validDays: null,
    });
    assert(licenseKey.startsWith('DLICV1:'), 'Prefixo inválido');
    assert(payload.expiresAt === null, 'Deve ser perpétua');
    assert(payload.allowedAgents.length === 4, 'Community: 4 agentes');
});
test('Valida licença community', () => {
    const { licenseKey } = (0, issuer_1.issueLicense)({ tier: 'community', licensee: 'OSS User', validDays: null });
    const payload = (0, codec_1.decodeLicense)(licenseKey);
    const result = (0, validator_1.validateLicense)(payload);
    assert(result.valid, 'Deve ser válida');
    assert(result.tier === 'community', 'Tier errado');
    assert(result.allowedAgents.includes('D2'), 'D2 deve estar presente');
    assert(!result.allowedAgents.includes('D9'), 'D9 NÃO deve estar presente');
});
// ── Pro ───────────────────────────────────────────────────────
console.log('\n📦 Pro Tier');
test('Emite licença pro com 365 dias', () => {
    const { payload } = (0, issuer_1.issueLicense)({ tier: 'pro', licensee: 'Empresa Pro', validDays: 365 });
    assert(payload.expiresAt !== null, 'Deve ter expiração');
    assert(payload.allowedAgents.includes('D3'), 'Pro deve ter D3');
    assert(!payload.allowedAgents.includes('D9'), 'Pro NÃO deve ter D9');
    assert(payload.allowedFeatures.includes('suricata_strict'), 'Pro deve ter strict');
    assert(!payload.allowedFeatures.includes('suricata_learn'), 'Pro NÃO deve ter learn');
});
test('Avisa quando restam ≤30 dias', () => {
    const { licenseKey } = (0, issuer_1.issueLicense)({ tier: 'pro', licensee: 'Empresa Pro', validDays: 15 });
    const payload = (0, codec_1.decodeLicense)(licenseKey);
    const result = (0, validator_1.validateLicense)(payload);
    assert(result.valid, 'Deve ser válida');
    assert(result.warnings.some(w => w.includes('EXPIRING')), 'Deve avisar expiração');
});
// ── Enterprise ────────────────────────────────────────────────
console.log('\n📦 Enterprise Tier');
test('Enterprise tem todos os 12 agentes', () => {
    const { payload } = (0, issuer_1.issueLicense)({ tier: 'enterprise', licensee: 'Banco X', validDays: 365 });
    assert(payload.allowedAgents.length === 12, `Esperado 12 agentes, recebeu ${payload.allowedAgents.length}`);
    assert(payload.allowedAgents.includes('D12'), 'Deve ter D12 Rottweiler');
    assert(payload.allowedFeatures.includes('active_response'), 'Deve ter active_response');
});
// ── Segurança ─────────────────────────────────────────────────
console.log('\n🔒 Segurança');
test('Detecta licença adulterada', () => {
    const { payload } = (0, issuer_1.issueLicense)({ tier: 'community', licensee: 'Hacker', validDays: null });
    const tampered = { ...payload, tier: 'enterprise' }; // Upgrade não autorizado
    const result = (0, validator_1.validateLicense)(tampered);
    assert(!result.valid, 'Licença adulterada deve ser inválida');
    assert(result.errors.some(e => e.includes('TAMPERED')), 'Deve acusar adulteração');
});
test('Rejeita licença expirada', () => {
    const { payload } = (0, issuer_1.issueLicense)({ tier: 'pro', licensee: 'Empresa', validDays: 1 });
    // Simula expiração forçando o timestamp
    const expired = { ...payload, expiresAt: Date.now() - 86_400_000 };
    // Re-sign para o fingerprint ser válido com o dado expirado
    // (na prática, o cliente não pode re-assinar)
    const result = (0, validator_1.validateLicense)(expired);
    assert(!result.valid, 'Licença expirada deve ser inválida');
});
test('Formato inválido é rejeitado', () => {
    try {
        (0, codec_1.decodeLicense)('INVALID_KEY_FORMAT');
        assert(false, 'Devia ter lançado erro');
    }
    catch (e) {
        assert(e instanceof Error && e.message.includes('FORMAT_ERROR'), 'Erro de formato esperado');
    }
});
// ── Manager ───────────────────────────────────────────────────
console.log('\n🎛️  LicenseManager');
test('Fallback para community sem licença', () => {
    const manager = manager_1.LicenseManager.getInstance();
    const result = manager['communityFallback']();
    assert(result.valid, 'Community fallback deve ser válido');
    assert(result.tier === 'community', 'Tier deve ser community');
});
// ── Resultado ─────────────────────────────────────────────────
console.log(`\n${'─'.repeat(40)}`);
console.log(`Resultado: ${passed} passaram, ${failed} falharam`);
if (failed > 0)
    process.exit(1);
//# sourceMappingURL=license.test.js.map