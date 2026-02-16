// ============================================================
// Dalion License System — LicenseManager Singleton
// Interface principal usada por todos os agentes do Dalion
// ============================================================

import { decodeLicense } from './codec';
import { validateLicense, assertAgentAllowed, assertFeatureAllowed } from './validator';
import type { AgentId, Feature, ValidationResult } from './types';

const COMMUNITY_LICENSE_KEY = process.env.DALION_LICENSE_KEY ?? null;

export class LicenseManager {
  private static instance: LicenseManager;
  private result: ValidationResult | null = null;

  private constructor() { }

  static getInstance(): LicenseManager {
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
  initialize(licenseKey?: string): ValidationResult {
    const key = licenseKey ?? COMMUNITY_LICENSE_KEY;

    if (!key) {
      // Fallback para community sem licença
      this.result = this.communityFallback();
      this.printBanner();
      return this.result;
    }

    try {
      const payload = decodeLicense(key);
      this.result = validateLicense(payload);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      this.result = this.errorFallback(msg);
    }

    this.printBanner();
    return this.result;
  }

  /** Retorna o resultado de validação atual. */
  getResult(): ValidationResult {
    if (!this.result) {
      throw new Error('LicenseManager não foi inicializado. Chame initialize() no bootstrap.');
    }
    return this.result;
  }

  /** Verifica se um agente pode ser executado. */
  canRunAgent(agentId: AgentId): boolean {
    return this.getResult().valid && this.getResult().allowedAgents.includes(agentId);
  }

  /** Verifica se uma feature está disponível. */
  hasFeature(feature: Feature): boolean {
    return this.getResult().valid && this.getResult().allowedFeatures.includes(feature);
  }

  /** Lança erro se o agente não estiver autorizado. */
  requireAgent(agentId: AgentId): void {
    assertAgentAllowed(this.getResult(), agentId);
  }

  /** Lança erro se a feature não estiver autorizada. */
  requireFeature(feature: Feature): void {
    assertFeatureAllowed(this.getResult(), feature);
  }

  // ── Private ────────────────────────────────────────────────

  private communityFallback(): ValidationResult {
    return {
      valid: true,
      tier: 'community',
      licensee: 'Open Source User',
      expiresAt: null,
      daysRemaining: null,
      allowedAgents: ['D1', 'D2', 'D10', 'D11'],
      allowedFeatures: [],
      maxEventsPerSecond: Infinity,  // Ilimitado
      warnings: ['Rodando em modo Community. Upgrade em codeark.com.br'],
      errors: [],
    };
  }

  private errorFallback(error: string): ValidationResult {
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

  private printBanner(): void {
    const r = this.result!;
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

    for (const w of r.warnings) console.warn(`  ⚠️  ${w}`);
    for (const e of r.errors) console.error(`  ❌ ${e}`);
    console.log('');
  }
}

// Export da instância singleton
export const licenseManager = LicenseManager.getInstance();
