import type { LicensePayload, Tier } from './types';
export interface IssueOptions {
    tier: Tier;
    licensee: string;
    /** Dias de validade. null = perpétua (só community) */
    validDays: number | null;
}
/**
 * Emite uma nova licença assinada.
 * Retorna a string de licença codificada (para enviar ao cliente)
 * e o payload completo (para salvar no backoffice).
 */
export declare function issueLicense(options: IssueOptions): {
    licenseKey: string;
    payload: LicensePayload;
};
//# sourceMappingURL=issuer.d.ts.map