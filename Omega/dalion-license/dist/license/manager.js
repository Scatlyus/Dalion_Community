"use strict";
// ============================================================
// Dalion License System — LicenseManager Singleton
// Interface principal usada por todos os agentes do Dalion
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.licenseManager = exports.LicenseManager = void 0;
const codec_1 = require("./codec");
const validator_1 = require("./validator");
const COMMUNITY_LICENSE_KEY = process.env.DALION_LICENSE_KEY ?? null;
class LicenseManager {
    static instance;
    result = null;
    constructor() { }
    static getInstance() {
        if (!LicenseManager.instance) {
            LicenseManager.instance = new LicenseManager();
        }
        return LicenseManager.instance;
    }
    /**
     * Inicializa o LicenseManager.
     * Deve ser chamado UMA VEZ no bootstrap da aplicação.
     *
     * @param licenseKey - String DLICV1:... (de env var ou arquivo .license)
     *                     Se omitido, ativa modo Community automaticamente.
     */
    initialize(licenseKey) {
        const key = licenseKey ?? COMMUNITY_LICENSE_KEY;
        if (!key) {
            // Fallback para community sem licença
            this.result = this.communityFallback();
            this.printBanner();
            return this.result;
        }
        try {
            const payload = (0, codec_1.decodeLicense)(key);
            this.result = (0, validator_1.validateLicense)(payload);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            this.result = this.errorFallback(msg);
        }
        this.printBanner();
        return this.result;
    }
    /** Retorna o resultado de validação atual. */
    getResult() {
        if (!this.result) {
            throw new Error('LicenseManager não foi inicializado. Chame initialize() no bootstrap.');
        }
        return this.result;
    }
    /** Verifica se um agente pode ser executado. */
    canRunAgent(agentId) {
        return this.getResult().valid && this.getResult().allowedAgents.includes(agentId);
    }
    /** Verifica se uma feature está disponível. */
    hasFeature(feature) {
        return this.getResult().valid && this.getResult().allowedFeatures.includes(feature);
    }
    /** Lança erro se o agente não estiver autorizado. */
    requireAgent(agentId) {
        (0, validator_1.assertAgentAllowed)(this.getResult(), agentId);
    }
    /** Lança erro se a feature não estiver autorizada. */
    requireFeature(feature) {
        (0, validator_1.assertFeatureAllowed)(this.getResult(), feature);
    }
    // ── Private ────────────────────────────────────────────────
    communityFallback() {
        return {
            valid: true,
            tier: 'community',
            licensee: 'Open Source User',
            expiresAt: null,
            daysRemaining: null,
            allowedAgents: ['D1', 'D2', 'D10', 'D11'],
            allowedFeatures: [],
            maxEventsPerSecond: Infinity, // Ilimitado
            warnings: ['Rodando em modo Community. Upgrade em codeark.com.br'],
            errors: [],
        };
    }
    errorFallback(error) {
        return {
            valid: false,
            tier: 'community',
            licensee: 'INVALID',
            expiresAt: null,
            daysRemaining: null,
            allowedAgents: [],
            allowedFeatures: [],
            maxEventsPerSecond: 0,
            warnings: [],
            errors: [error],
        };
    }
    printBanner() {
        const r = this.result;
        const tierLabel = r.tier.toUpperCase().padEnd(12);
        const status = r.valid ? '✅ VÁLIDA' : '❌ INVÁLIDA';
        console.log('\n╔═══════════════════════════════════════╗');
        console.log(`║     🧭 DALION — LICENSE STATUS        ║`);
        console.log('╠═══════════════════════════════════════╣');
        console.log(`║  Tier:     ${tierLabel}               ║`);
        console.log(`║  Status:   ${status}                  ║`);
        console.log(`║  Licensee: ${r.licensee.substring(0, 27).padEnd(27)} ║`);
        console.log(`║  Agentes:  ${String(r.allowedAgents.length).padEnd(27)} ║`);
        console.log('╚═══════════════════════════════════════╝');
        for (const w of r.warnings)
            console.warn(`  ⚠️  ${w}`);
        for (const e of r.errors)
            console.error(`  ❌ ${e}`);
        console.log('');
    }
}
exports.LicenseManager = LicenseManager;
// Export da instância singleton
exports.licenseManager = LicenseManager.getInstance();
//# sourceMappingURL=manager.js.map