// ============================================================
// Dalion License System — Encoder / Decoder
// Formato: base64(JSON(LicensePayload))
// ============================================================

import type { LicensePayload } from './types';

const LICENSE_PREFIX = 'DLICV1:';

/**
 * Encoda um payload assinado para uma string de licença portável.
 * Exemplo: DLICV1:eyJ0aWVyIjoicHJvIiwi...
 */
export function encodeLicense(payload: LicensePayload): string {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json, 'utf8').toString('base64');
  return `${LICENSE_PREFIX}${b64}`;
}

/**
 * Decoda uma string de licença de volta para o payload.
 * Lança erro se o formato for inválido.
 */
export function decodeLicense(licenseString: string): LicensePayload {
  const trimmed = licenseString.trim();

  if (!trimmed.startsWith(LICENSE_PREFIX)) {
    throw new Error(
      `LICENSE_FORMAT_ERROR: Licença deve começar com "${LICENSE_PREFIX}"`,
    );
  }

  const b64 = trimmed.slice(LICENSE_PREFIX.length);

  let json: string;
  try {
    json = Buffer.from(b64, 'base64').toString('utf8');
  } catch {
    throw new Error('LICENSE_DECODE_ERROR: Falha ao decodificar base64.');
  }

  let payload: unknown;
  try {
    payload = JSON.parse(json);
  } catch {
    throw new Error('LICENSE_PARSE_ERROR: JSON inválido no payload da licença.');
  }

  // Validação estrutural mínima
  const required = ['tier','licensee','licenseId','issuedAt','expiresAt',
                    'allowedAgents','allowedFeatures','maxEventsPerSecond','fingerprint'];
  for (const field of required) {
    if (!(field in (payload as object))) {
      throw new Error(`LICENSE_MISSING_FIELD: Campo "${field}" ausente na licença.`);
    }
  }

  return payload as LicensePayload;
}
