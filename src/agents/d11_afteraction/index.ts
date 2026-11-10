import { PipelineContext, FeedbackResult, ReinforcementSignal, LessonLearned } from './types';
import { ThreatType } from '../d10_ethos/types';
import { StrategicDecision } from '../d12_rottweiler/types';

export class DalionAfterAction {

    constructor() {
        console.log("🔧 D11 AfterAction initialized.");
    }

    /**
     * Registra o resultado de uma decisão estratégica para aprendizado futuro
     */
    public record(decision: StrategicDecision, outcome: string): LessonLearned {
        const effectiveness = outcome === 'success' ? 1.0 : outcome === 'partial' ? 0.5 : 0;

        const reinforcement = effectiveness > 0.8
            ? `Reinforce action ${decision.action} for similar triggers.`
            : `Review thresholds for ${decision.reason}.`;

        return {
            decision_id: `DEC-${Date.now()}`,
            action: decision.action,
            outcome: outcome,
            effectiveness,
            reinforcement,
            timestamp: new Date().toISOString()
        };
    }

    public analyze(context: PipelineContext): FeedbackResult {
        const signals: ReinforcementSignal[] = [];
        let feedbackType: 'POSITIVE_REINFORCEMENT' | 'NEGATIVE_CORRECTION' | 'ANOMALY_FLAG' | 'NEUTRAL' = 'NEUTRAL';
        let needsReview = false;

        // 1. Battle Damage Assessment (BDA)
        // Did the action succeed?
        const actionSuccess = context.execution.success;

        // 2. Conflict Detection (D12 Override vs D10 Verdict)
        const d10Verdict = context.classification.threat_type;
        const d12Action = context.decision.action;

        // Scenario A: D10 says CLEAN/UNKNOWN, but D12 says BLOCK/QUARANTINE (False Negative in D10?)
        if ((d10Verdict === ThreatType.UNKNOWN || d10Verdict === ThreatType.CLEAN) &&
            (d12Action === 'BLOCK' || d12Action === 'QUARANTINE')) {

            feedbackType = 'ANOMALY_FLAG';
            needsReview = true;
            signals.push({
                target_agent: 'D10',
                adjustment_factor: 0,
                reason: `D12 Override: Action ${d12Action} taken despite D10 verdict ${d10Verdict}. Possible False Negative.`
            });
        }


        // Scenario B: D10 says MALWARE/RANSOMWARE confidence > 0.9 and Action was BLOCK (Success)
        // Positive Reinforcement for D2 rules that triggered this.
        if (context.execution.success && ['BLOCK', 'QUARANTINE', 'ISOLATE_HOST'].includes(d12Action) &&
            (d10Verdict === ThreatType.MALWARE || d10Verdict === ThreatType.RANSOMWARE) &&
            context.classification.confidence >= 0.9) {

            feedbackType = 'POSITIVE_REINFORCEMENT';

            // Reinforce D2 Tags involved
            (context.enriched.tags || []).forEach(tag => {
                signals.push({
                    target_agent: 'D2',
                    rule_id: tag,
                    adjustment_factor: 0.05,
                    reason: `High confidence successful interdiction for tag ${tag}`
                });
            });
        }

        const bdaSummary = `Action: ${d12Action} | Success: ${actionSuccess} | Latency: ${context.latency_ms || 'N/A'}ms | Feedback: ${feedbackType}`;

        return {
            feedback_type: feedbackType,
            signals,
            bda_summary: bdaSummary,
            needs_human_review: needsReview
        };
    }
}
