"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DalionSentinela = void 0;
const RulesEngine_1 = require("../core/rules/RulesEngine");
class DalionSentinela {
    engine;
    constructor() {
        this.engine = new RulesEngine_1.RulesEngine();
    }
    async analyze(log) {
        console.log(`[D2 Sentinela] Analisando log: ${log.source} | TS: ${log.timestamp}`);
        const result = this.engine.evaluate(log);
        if (result.detected) {
            const topMatch = result.matches[0];
            const signal = {
                agentId: 'D2_SENTINELA',
                tier: 'TX.Ω',
                timestamp: new Date().toISOString(),
                confidence: result.totalScore,
                entropy: 1 - result.totalScore, // Simulação simples de entropia
                evidence: {
                    matched_rules: result.matches.map(r => r.id),
                    primary_anomaly: topMatch.anomaly_type,
                    target_ip: log.source_ip || log.dest_ip
                }
            };
            console.log(`[D2 Sentinela] ⚠️  Deteção confirmada por ${result.matches.length} regras.`);
            return signal;
        }
        return null;
    }
}
exports.DalionSentinela = DalionSentinela;
