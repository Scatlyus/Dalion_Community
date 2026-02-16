import type { LicensePayload } from './types';
/**
 * Gera o fingerprint HMAC-SHA256 de um payload.
 */
export declare function signPayload(payload: Omit<LicensePayload, 'fingerprint'>): string;
/**
 * Verifica se o fingerprint do payload é válido.
 * Usa timingSafeEqual para evitar timing attacks.
 */
export declare function verifyFingerprint(payload: LicensePayload): boolean;
//# sourceMappingURL=signer.d.ts.map