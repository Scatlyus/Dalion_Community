// ============================================================
// Dalion License System — Issuer (USO INTERNO CODEARK)
// Gera licenças assinadas para distribuição aos clientes
// ============================================================

import { randomUUID } from 'crypto';
import { signPayload } from './signer';
import { encodeLicense } from './codec';
import { TIER_AGENTS, TIER_FEATURES, TIER_EPS_LIMIT } from './tiers';
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
export function issueLicense(options: IssueOptions): {
  licenseKey: string;
  payload: LicensePayload;
} {
  const { tier, licensee, validDays } = options;

  const now = Date.now();
  const expiresAt = validDays !== null ? now + validDays * 86_400_000 : null;

  const base: Omit<LicensePayload, 'fingerprint'> = {
    tier,
    licensee,
    licenseId: randomUUID(),
    issuedAt: now,
    expiresAt,
    allowedAgents: TIER_AGENTS[tier],
    allowedFeatures: TIER_FEATURES[tier],
    maxEventsPerSecond: TIER_EPS_LIMIT[tier],  // Agora é Infinity para todos os tiers
  };

  const fingerprint = signPayload(base);
  const payload: LicensePayload = { ...base, fingerprint };
  const licenseKey = encodeLicense(payload);

  return { licenseKey, payload };
}
