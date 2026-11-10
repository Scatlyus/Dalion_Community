import { EpistemicSignal, DecisionRecord } from '../../types/omega';
import { DalionEventBus } from '../bus/DalionEventBus';

export class SovereignTriad {
    private signals = new Map<string, { tx?: EpistemicSignal; te?: EpistemicSignal }>();

    constructor(private readonly bus?: DalionEventBus) {
        console.log("[Ω SovereignTriad] Inicializado. Aguardando convergência da Tríade...");
    }

    /**
     * Registra sinais vindos do Olho (D2 - TX) ou da Mente (D10 - TE)
     */
    public async registerSignal(signal: EpistemicSignal): Promise<void> {
        const { event_id, target_ip } = signal.evidence || {};
        if (typeof event_id !== 'string' || !event_id.trim() || typeof target_ip !== 'string' || !target_ip.trim() || target_ip === 'unknown') return;
        if (signal.tier !== 'TX.Ω' && signal.tier !== 'TE.Ω') return;
        const key = JSON.stringify([event_id, target_ip]);
        const pair = this.signals.get(key) || {};
        if (signal.tier === 'TX.Ω') pair.tx = signal;
        else pair.te = signal;
        this.signals.set(key, pair);
        if (this.signals.size > 1000) this.signals.delete(this.signals.keys().next().value!);
        console.log(`[Ω Triad] Sinal recebido de ${signal.agentId} (${signal.tier}) | Confiança: ${signal.confidence}`);

        await this.evaluateConsensus(key);
    }

    /**
     * Avalia se há consenso soberano para disparar o "Bite" (Mandíbula)
     */
    private async evaluateConsensus(key: string): Promise<void> {
        const { tx: txSignal, te: teSignal } = this.signals.get(key) || {};

        if (txSignal && teSignal) {
            this.signals.delete(key);
            const jointConfidence = (txSignal.confidence + teSignal.confidence) / 2;

            if (jointConfidence > 0.85) {
                console.log(`[Ω Consensus] ✅ Consenso atingido! Confiança conjunta: ${jointConfidence}`);
                await this.triggerBite(txSignal, teSignal);
            } else {
                console.log(`[Ω Triad] Aguardando maior confiança ou evidência adicional.`);
            }
        }
    }

    private async triggerBite(tx: EpistemicSignal, te: EpistemicSignal): Promise<void> {
        console.log("[Ω Action] Disparando D12_Rottweiler (TA.Ω) para execução de contenção...");

        const record: DecisionRecord = {
            id: `Ω-${Date.now()}`,
            policy: "NET_EGRESS_TO_MALICIOUS_IP",
            action: "BLOCK_IP",
            target: tx.evidence.target_ip || "unknown",
            severity: "CRITICAL",
            consensus: true,
            timestamp: new Date().toISOString()
        };

        console.log(`[Ω Audit] Ação registrada: ${JSON.stringify(record, null, 2)}`);

        // Publica o consenso no barramento para que ArqosBridge e outros possam reagir
        this.bus?.publish({ type: 'OMEGA_CONSENSUS', payload: record });

    }
}
