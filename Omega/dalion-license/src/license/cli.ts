#!/usr/bin/env node
// ============================================================
// Dalion License System — CLI (USO INTERNO CODEARK)
// ============================================================
// Uso:
//   npx ts-node src/license/cli.ts issue --tier pro --licensee "Empresa X" --days 365
//   npx ts-node src/license/cli.ts inspect DLICV1:eyJ...
// ============================================================

import { issueLicense } from './issuer';
import { decodeLicense } from './codec';
import { validateLicense } from './validator';
import { AGENT_NAMES } from './tiers';
import type { Tier } from './types';

const [,, command, ...args] = process.argv;

function parseFlags(args: string[]): Record<string, string> {
  const flags: Record<string, string> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      flags[args[i].slice(2)] = args[i + 1] ?? 'true';
      i++;
    }
  }
  return flags;
}

switch (command) {

  // ── issue ──────────────────────────────────────────────────
  case 'issue': {
    const flags = parseFlags(args);
    const tier = flags.tier as Tier;
    const licensee = flags.licensee;
    const days = flags.days ? parseInt(flags.days) : null;

    if (!tier || !licensee) {
      console.error('Uso: cli.ts issue --tier <community|pro|enterprise> --licensee "Nome" [--days 365]');
      process.exit(1);
    }

    const { licenseKey, payload } = issueLicense({ tier, licensee, validDays: days });

    console.log('\n╔══════════════════ LICENÇA EMITIDA ══════════════════╗');
    console.log(`║  ID:       ${payload.licenseId}`);
    console.log(`║  Tier:     ${payload.tier}`);
    console.log(`║  Licensee: ${payload.licensee}`);
    console.log(`║  Emitida:  ${new Date(payload.issuedAt).toISOString()}`);
    console.log(`║  Expira:   ${payload.expiresAt ? new Date(payload.expiresAt).toISOString() : 'Nunca (perpétua)'}`);
    console.log(`║  EPS Max:  ${payload.maxEventsPerSecond.toLocaleString()}`);
    console.log(`║  Agentes:  ${payload.allowedAgents.join(', ')}`);
    console.log('╠══════════════════════════════════════════════════════╣');
    console.log('║  LICENSE KEY (enviar ao cliente):');
    console.log(`║`);
    console.log(`  ${licenseKey}`);
    console.log(`║`);
    console.log('╚══════════════════════════════════════════════════════╝\n');
    break;
  }

  // ── inspect ────────────────────────────────────────────────
  case 'inspect': {
    const key = args[0];
    if (!key) {
      console.error('Uso: cli.ts inspect <DLICV1:...>');
      process.exit(1);
    }

    try {
      const payload = decodeLicense(key);
      const result = validateLicense(payload);

      console.log('\n╔══════════════════ INSPEÇÃO DE LICENÇA ══════════════╗');
      console.log(`║  Status:   ${result.valid ? '✅ VÁLIDA' : '❌ INVÁLIDA'}`);
      console.log(`║  Tier:     ${result.tier}`);
      console.log(`║  Licensee: ${result.licensee}`);
      console.log(`║  Expira:   ${result.expiresAt ? new Date(result.expiresAt).toISOString() : 'Nunca'}`);
      if (result.daysRemaining !== null) {
        console.log(`║  Restam:   ${result.daysRemaining} dias`);
      }
      console.log('╠══════════════════════════════════════════════════════╣');
      console.log('║  Agentes liberados:');
      for (const a of result.allowedAgents) {
        console.log(`║    ${a} — ${AGENT_NAMES[a]}`);
      }
      if (result.allowedFeatures.length > 0) {
        console.log('║  Features liberadas:');
        for (const f of result.allowedFeatures) {
          console.log(`║    • ${f}`);
        }
      }
      if (result.warnings.length > 0) {
        console.log('║  ⚠️  Avisos:');
        for (const w of result.warnings) console.log(`║    ${w}`);
      }
      if (result.errors.length > 0) {
        console.log('║  ❌ Erros:');
        for (const e of result.errors) console.log(`║    ${e}`);
      }
      console.log('╚══════════════════════════════════════════════════════╝\n');
    } catch (err: unknown) {
      console.error('Erro ao inspecionar licença:', err instanceof Error ? err.message : err);
      process.exit(1);
    }
    break;
  }

  default:
    console.error('Comandos disponíveis: issue | inspect');
    process.exit(1);
}
