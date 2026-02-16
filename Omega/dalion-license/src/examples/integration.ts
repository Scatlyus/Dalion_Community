// ============================================================
// Dalion License System — Exemplo de Integração nos Agentes
// ============================================================

import { licenseManager } from '../license/index';

// ──────────────────────────────────────────────────────────────
// 1. BOOTSTRAP (index.ts / main.ts da aplicação)
// ──────────────────────────────────────────────────────────────

// A chave vem da variável de ambiente DALION_LICENSE_KEY
// Se não existir, ativa Community automaticamente.
licenseManager.initialize();

// Ou passar a chave explicitamente:
// licenseManager.initialize(process.env.DALION_LICENSE_KEY);


// ──────────────────────────────────────────────────────────────
// 2. NOS AGENTES — Padrão recomendado
// ──────────────────────────────────────────────────────────────

// Exemplo: D3 Espionagem (Pro+)
export async function runEspionagem(event: unknown) {
  // Lança erro descritivo se não tiver a licença correta
  licenseManager.requireAgent('D3');

  console.log('D3 Espionagem: Iniciando enriquecimento...');
  // ... lógica do agente
}

// Exemplo: D9 AttackGraph (Enterprise only)
export async function runAttackGraph(event: unknown) {
  licenseManager.requireAgent('D9');
  licenseManager.requireFeature('attack_graph');

  console.log('D9 AttackGraph: Gerando grafo de ataque...');
  // ... lógica do agente
}

// Exemplo: Verificação condicional sem lançar erro
export async function runPipeline(event: unknown) {
  const result = licenseManager.getResult();

  // Agentes base — sempre disponíveis
  console.log('D2 Sentinela: Analisando evento...');

  // Agentes condicionais
  if (licenseManager.canRunAgent('D3')) {
    console.log('D3 Espionagem: Enriquecendo IOCs...');
  }

  if (licenseManager.canRunAgent('D9')) {
    console.log('D9 AttackGraph: Gerando predição...');
  }

  // Feature condicional
  if (licenseManager.hasFeature('suricata_learn')) {
    console.log('AfterAction: Modo --learn ativo.');
  }

  console.log(`Pipeline concluído. Tier: ${result.tier} | EPS máx: ${result.maxEventsPerSecond}`);
}


// ──────────────────────────────────────────────────────────────
// 3. SURICATA INGESTOR — Verificação de flags
// ──────────────────────────────────────────────────────────────

export function checkSuricataFlags(flags: { learn?: boolean; strict?: boolean }) {
  if (flags.learn) {
    licenseManager.requireFeature('suricata_learn');
  }
  if (flags.strict) {
    licenseManager.requireFeature('suricata_strict');
  }
}
