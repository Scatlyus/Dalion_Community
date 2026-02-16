// ============================================================
// Dalion License System — Offline HMAC Signer
// Uses Node.js built-in crypto — zero external dependencies
// ============================================================

import { createHmac, timingSafeEqual } from 'crypto';
import type { LicensePayload } from './types';

/**
 * SIGNING_SECRET deve ser uma variável de ambiente no ambiente de EMISSÃO.
 * Nunca exposta ao cliente — usada apenas internamente na CodeArk.
 *
 * Em produção: process.env.DALION_SIGNING_SECRET
 */
const SIGNING_SECRET =
  process.env.DALION_SIGNING_SECRET ?? 'dev-secret-replace-in-production';

/**
 * Serializa o payload de forma determinística para o HMAC.
 * Exclui o campo `fingerprint` do hash.
 */
function serializeForSigning(payload: Omit<LicensePayload, 'fingerprint'>): string {
  return JSON.stringify({
    tier:               payload.tier,
    licensee:           payload.licensee,
    licenseId:          payload.licenseId,
    issuedAt:           payload.issuedAt,
    expiresAt:          payload.expiresAt,
    allowedAgents:      [...payload.allowedAgents].sort(),
    allowedFeatures:    [...payload.allowedFeatures].sort(),
    maxEventsPerSecond: payload.maxEventsPerSecond,
  });
}

/**
 * Gera o fingerprint HMAC-SHA256 de um payload.
 */
export function signPayload(payload: Omit<LicensePayload, 'fingerprint'>): string {
  return createHmac('sha256', SIGNING_SECRET)
    .update(serializeForSigning(payload))
    .digest('hex');
}

/**
 * Verifica se o fingerprint do payload é válido.
 * Usa timingSafeEqual para evitar timing attacks.
 */
export function verifyFingerprint(payload: LicensePayload): boolean {
  const expected = signPayload(payload);
  try {
    return timingSafeEqual(
      Buffer.from(payload.fingerprint, 'hex'),
      Buffer.from(expected, 'hex'),
    );
  } catch {
    return false;
  }
}
