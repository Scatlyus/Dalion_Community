"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const SovereignTriad_1 = require("./src/core/triad/SovereignTriad");
const d2_sentinela_1 = require("./src/agents/d2_sentinela");
const d10_ethos_1 = require("./src/agents/d10_ethos");
const d12_rottweiler_1 = require("./src/agents/d12_rottweiler");
async function main() {
    console.log("=== 🧪 DALION VR01: SMOKE TEST (Ω LAYER) ===");
    const triad = new SovereignTriad_1.SovereignTriad();
    const sentinela = new d2_sentinela_1.DalionSentinela();
    const ethos = new d10_ethos_1.DalionEthos();
    const rottweiler = new d12_rottweiler_1.DalionRottweiler();
    // Dataset Simulado
    const log = {
        event_id: 'smk-001',
        log_source_id: 'KC7_EmailLogs',
        timestamp: new Date().toISOString(),
        source_ip: "10.0.0.45",
        email_sender: "it-support@microsoft-security-verify.com",
        action: 'url_click',
        status: 'success',
        severity: 'high',
        message: 'Potential phishing link click'
    };
    // 1. O Olho Detecta (TX)
    const txResult = await sentinela.analyze(log);
    if (txResult.anomaly) {
        // Convert to EpistemicSignal for Triad
        const txSignal = {
            agentId: 'D2_Sentinela',
            tier: 'TX.Ω',
            timestamp: new Date().toISOString(),
            confidence: txResult.anomaly_score / 100,
            entropy: 0.5,
            evidence: txResult
        };
        // 2. A Mente Classifica (TE)
        // Mocking an EnrichedIOC for D10 based on D2 results
        const enriched = {
            ioc_value: log.source_ip,
            ioc_type: 'IP',
            is_anomaly: txResult.anomaly,
            source: 'EDR',
            last_enriched: log.timestamp,
            threat_score: txResult.anomaly_score,
            confidence: 0.9,
            reputation: 'suspicious',
            tags: txResult.tags,
            context: log,
            enrichment: {}
        };
        const teResult = await ethos.classify(enriched);
        const teSignal = {
            agentId: 'D10_Ethos',
            tier: 'TE.Ω',
            timestamp: new Date().toISOString(),
            confidence: teResult.confidence,
            entropy: 0.1,
            evidence: teResult
        };
        // 3. O Orquestrador Consolida Consenso
        await triad.registerSignal(txSignal);
        await triad.registerSignal(teSignal);
        console.log(`\n[Ω Decision] Ação Recomendada: ${teResult.recommended_action.toUpperCase()}`);
    }
    else {
        console.log("⚪ D2 Sentinela: Nenhuma anomalia detectada.");
    }
}
main().catch(console.error);
