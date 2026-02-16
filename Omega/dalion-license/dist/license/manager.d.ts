import type { AgentId, Feature, ValidationResult } from './types';
export declare class LicenseManager {
    private static instance;
    private result;
    private constructor();
    static getInstance(): LicenseManager;
    /**
     * Inicializa o LicenseManager.
     * Deve ser chamado UMA VEZ no bootstrap da aplicação.
     *
     * @param licenseKey - String DLICV1:... (de env var ou arquivo .license)
     *                     Se omitido, ativa modo Community automaticamente.
     */
    initialize(licenseKey?: string): ValidationResult;
    /** Retorna o resultado de validação atual. */
    getResult(): ValidationResult;
    /** Verifica se um agente pode ser executado. */
    canRunAgent(agentId: AgentId): boolean;
    /** Verifica se uma feature está disponível. */
    hasFeature(feature: Feature): boolean;
    /** Lança erro se o agente não estiver autorizado. */
    requireAgent(agentId: AgentId): void;
    /** Lança erro se a feature não estiver autorizada. */
    requireFeature(feature: Feature): void;
    private communityFallback;
    private errorFallback;
    private printBanner;
}
export declare const licenseManager: LicenseManager;
//# sourceMappingURL=manager.d.ts.map