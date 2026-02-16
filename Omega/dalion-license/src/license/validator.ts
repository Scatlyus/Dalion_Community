// ============================================================
// Dalion License System — Core Validator (Offline)
// ============================================================

import { verifyFingerprint } from './signer';
import { TIER_AGENTS, TIER_FEATURES, TIER_EPS_LIMIT } from './tiers';
import type {
  AgentId,
  Feature,
  LicensePayload,
  ValidationResult,
} from './types';

const WARNING_DAYS = 30; // Avisa quando restam X dias

/**
 * Valida uma licença completamente offline.
 * 1. Verifica integridade HMAC (anti-tamper)
 * 2. Verifica expiração
 * 3. Verifica se agentes/features do payload estão dentro do tier declarado
 */
export function validateLicense(payload: LicensePayload): ValidationResult {
  const warnings: string[] = [];
  const errors: string[] = [];

  // ── 1. Integridade HMAC ──────────────────────────────────
  if (!verifyFingerprint(payload)) {
    errors.push('LICENSE_TAMPERED: Fingerprint inválido. Licença rejeitada.');
    return buildResult(payload, warnings, errors);
  }

  // ── 2. Expiração ─────────────────────────────────────────
  let daysRemaining: number | null = null;
  if (payload.expiresAt !== null) {
    const now = Date.now();
    daysRemaining = Math.floor((payload.expiresAt - now) / 86_400_000);

    if (daysRemaining < 0) {
      errors.push(`LICENSE_EXPIRED: Licença expirou há ${Math.abs(daysRemaining)} dias.`);
      return buildResult(payload, warnings, errors);
    }

    if (daysRemaining <= WARNING_DAYS) {
      warnings.push(`LICENSE_EXPIRING_SOON: ${daysRemaining} dias restantes.`);
    }
  }

  // ── 3. Consistência do tier ──────────────────────────────
  const tierAgents = TIER_AGENTS[payload.tier];
  const tierFeatures = TIER_FEATURES[payload.tier];
  const tierEps = TIER_EPS_LIMIT[payload.tier];

  const unauthorizedAgents = payload.allowedAgents.filter(
    (a) => !tierAgents.includes(a),
  );
  if (unauthorizedAgents.length > 0) {
    errors.push(
      `LICENSE_INVALID_AGENTS: Agentes não permitidos no tier "${payload.tier}": ${unauthorizedAgents.join(', ')}`,
    );
  }

  const unauthorizedFeatures = payload.allowedFeatures.filter(
    (f) => !tierFeatures.includes(f),
  );
  if (unauthorizedFeatures.length > 0) {
    errors.push(
      `LICENSE_INVALID_FEATURES: Features não permitidas no tier "${payload.tier}": ${unauthorizedFeatures.join(', ')}`,
    );
  }

  // EPS agora é ilimitado — não validamos mais este campo
  // Warning de performance (se necessário) é tratado em runtime, não na licença

  return buildResult(payload, warnings, errors, daysRemaining);
}

// ── Helpers ──────────────────────────────────────────────────

function buildResult(
  payload: LicensePayload,
  warnings: string[],
  errors: string[],
  daysRemaining: number | null = null,
): ValidationResult {
  return {
    valid: errors.length === 0,
    tier: payload.tier,
    licensee: payload.licensee,
    expiresAt: payload.expiresAt,
    daysRemaining,
    allowedAgents: errors.length === 0 ? payload.allowedAgents : [],
    allowedFeatures: errors.length === 0 ? payload.allowedFeatures : [],
    maxEventsPerSecond: errors.length === 0 ? payload.maxEventsPerSecond : 0,
    warnings,
    errors,
  };
}

// ── Guard helpers para uso no pipeline de agentes ────────────

/**
 * Lança erro se o agente não estiver autorizado na licença atual.
 */
export function assertAgentAllowed(
  result: ValidationResult,
  agentId: AgentId,
): void {
  if (!result.valid) throw new Error(`Licença inválida. Agente ${agentId} bloqueado.`);
  if (!result.allowedAgents.includes(agentId)) {
    throw new Error(
      `AGENT_BLOCKED: ${agentId} não está incluído no tier "${result.tier}". ` +
      `Faça upgrade em codeark.com.br`,
    );
  }
}

/**
 * Lança erro se a feature não estiver autorizada na licença atual.
 */
export function assertFeatureAllowed(
  result: ValidationResult,
  feature: Feature,
): void {
  if (!result.valid) throw new Error(`Licença inválida. Feature ${feature} bloqueada.`);
  if (!result.allowedFeatures.includes(feature)) {
    throw new Error(
      `FEATURE_BLOCKED: "${feature}" não está incluída no tier "${result.tier}". ` +
      `Faça upgrade em codeark.com.br`,
    );
  }
}

// ── Runtime Performance Warning ──────────────────────────────

/**
 * Soft warning para uso em runtime (não afeta validação de licença).
 * Útil para alertar quando o sistema está processando volume alto.
 * 
 * Exemplo de uso no pipeline:
 *   const currentEPS = calculateCurrentEPS();
 *   checkEPSWarning(currentEPS);
 */
export function checkEPSWarning(currentEPS: number): void {
  const { EPS_WARNING_THRESHOLD } = require('./tiers');
  if (currentEPS > EPS_WARNING_THRESHOLD) {
    console.warn(
      `⚠️  PERFORMANCE WARNING: ${currentEPS} EPS excede threshold recomendado (${EPS_WARNING_THRESHOLD}). ` +
      `Considere escalar sua infraestrutura.`
    );
  }
}
