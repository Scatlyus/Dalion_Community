"use strict";
// ============================================================
// Dalion License System — Exemplo de Integração nos Agentes
// ============================================================
Object.defineProperty(exports, "__esModule", { value: true });
exports.runEspionagem = runEspionagem;
exports.runAttackGraph = runAttackGraph;
exports.runPipeline = runPipeline;
exports.checkSuricataFlags = checkSuricataFlags;
const index_1 = require("../license/index");
// ──────────────────────────────────────────────────────────────
// 1. BOOTSTRAP (index.ts / main.ts da aplicação)
// ──────────────────────────────────────────────────────────────
// A chave vem da variável de ambiente DALION_LICENSE_KEY
// Se não existir, ativa Community automaticamente.
index_1.licenseManager.initialize();
// Ou passar a chave explicitamente:
// licenseManager.initialize(process.env.DALION_LICENSE_KEY);
// ──────────────────────────────────────────────────────────────
// 2. NOS AGENTES — Padrão recomendado
// ──────────────────────────────────────────────────────────────
// Exemplo: D3 Espionagem (Pro+)
async function runEspionagem(event) {
    // Lança erro descritivo se não tiver a licença correta
    index_1.licenseManager.requireAgent('D3');
    console.log('D3 Espionagem: Iniciando enriquecimento...');
    // ... lógica do agente
}
// Exemplo: D9 AttackGraph (Enterprise only)
async function runAttackGraph(event) {
    index_1.licenseManager.requireAgent('D9');
    index_1.licenseManager.requireFeature('attack_graph');
    console.log('D9 AttackGraph: Gerando grafo de ataque...');
    // ... lógica do agente
}
// Exemplo: Verificação condicional sem lançar erro
async function runPipeline(event) {
    const result = index_1.licenseManager.getResult();
    // Agentes base — sempre disponíveis
    console.log('D2 Sentinela: Analisando evento...');
    // Agentes condicionais
    if (index_1.licenseManager.canRunAgent('D3')) {
        console.log('D3 Espionagem: Enriquecendo IOCs...');
    }
    if (index_1.licenseManager.canRunAgent('D9')) {
        console.log('D9 AttackGraph: Gerando predição...');
    }
    // Feature condicional
    if (index_1.licenseManager.hasFeature('suricata_learn')) {
        console.log('AfterAction: Modo --learn ativo.');
    }
    console.log(`Pipeline concluído. Tier: ${result.tier} | EPS máx: ${result.maxEventsPerSecond}`);
}
// ──────────────────────────────────────────────────────────────
// 3. SURICATA INGESTOR — Verificação de flags
// ──────────────────────────────────────────────────────────────
function checkSuricataFlags(flags) {
    if (flags.learn) {
        index_1.licenseManager.requireFeature('suricata_learn');
    }
    if (flags.strict) {
        index_1.licenseManager.requireFeature('suricata_strict');
    }
}
//# sourceMappingURL=integration.js.map