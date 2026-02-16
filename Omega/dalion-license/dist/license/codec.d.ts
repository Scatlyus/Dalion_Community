import type { LicensePayload } from './types';
/**
 * Encoda um payload assinado para uma string de licença portável.
 * Exemplo: DLICV1:eyJ0aWVyIjoicHJvIiwi...
 */
export declare function encodeLicense(payload: LicensePayload): string;
/**
 * Decoda uma string de licença de volta para o payload.
 * Lança erro se o formato for inválido.
 */
export declare function decodeLicense(licenseString: string): LicensePayload;
//# sourceMappingURL=codec.d.ts.map