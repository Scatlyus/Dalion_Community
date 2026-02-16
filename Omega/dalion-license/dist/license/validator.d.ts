import type { AgentId, Feature, LicensePayload, ValidationResult } from './types';
/**
 * Valida uma licença completamente offline.
 * 1. Verifica integridade HMAC (anti-tamper)
 * 2. Verifica expiração
 * 3. Verifica se agentes/features do payload estão dentro do tier declarado
 */
export declare function validateLicense(payload: LicensePayload): ValidationResult;
/**
 * Lança erro se o agente não estiver autorizado na licença atual.
 */
export declare function assertAgentAllowed(result: ValidationResult, agentId: AgentId): void;
/**
 * Lança erro se a feature não estiver autorizada na licença atual.
 */
export declare function assertFeatureAllowed(result: ValidationResult, feature: Feature): void;
/**
 * Soft warning para uso em runtime (não afeta validação de licença).
 * Útil para alertar quando o sistema está processando volume alto.
 *
 * Exemplo de uso no pipeline:
 *   const currentEPS = calculateCurrentEPS();
 *   checkEPSWarning(currentEPS);
 */
export declare function checkEPSWarning(currentEPS: number): void;
//# sourceMappingURL=validator.d.ts.map