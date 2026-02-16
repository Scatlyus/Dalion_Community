"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SovereignTriad = void 0;
class SovereignTriad {
    signals = [];
    constructor() {
        console.log("[Ω SovereignTriad] Inicializado. Aguardando convergência da Tríade...");
    }
    /**
     * Registra sinais vindos do Olho (D2 - TX) ou da Mente (D10 - TE)
     */
    async registerSignal(signal) {
        this.signals.push(signal);
        console.log(`[Ω Triad] Sinal recebido de ${signal.agentId} (${signal.tier}) | Confiança: ${signal.confidence}`);
        await this.evaluateConsensus();
    }
    /**
     * Avalia se há consenso soberano para disparar o "Bite" (Mandíbula)
     */
    async evaluateConsensus() {
        const txSignal = this.signals.find(s => s.tier === 'TX.Ω');
        const teSignal = this.signals.find(s => s.tier === 'TE.Ω');
        if (txSignal && teSignal) {
            const jointConfidence = (txSignal.confidence + teSignal.confidence) / 2;
            if (jointConfidence > 0.85) {
                console.log(`[Ω Consensus] ✅ Consenso atingido! Confiança conjunta: ${jointConfidence}`);
                await this.triggerBite(txSignal, teSignal);
            }
            else {
                console.log(`[Ω Triad] Aguardando maior confiança ou evidência adicional.`);
            }
        }
    }
    async triggerBite(tx, te) {
        console.log("[Ω Action] Disparando D12_Rottweiler (TA.Ω) para execução de contenção...");
        // Log de auditoria irretratável
        const record = {
            id: `Ω-${Date.now()}`,
            policy: "NET_EGRESS_TO_MALICIOUS_IP",
            action: "BLOCK_IP",
            target: tx.evidence.target_ip || "unknown",
            severity: "CRITICAL",
            consensus: true,
            timestamp: new Date().toISOString()
        };
        console.log(`[Ω Audit] Ação registrada: ${JSON.stringify(record, null, 2)}`);
    }
}
exports.SovereignTriad = SovereignTriad;
