import { SecurityEvent } from '../d2_sentinela/types';
import { EnrichedIOC } from '../d3_espionagem/types';
import { ClassificationResult } from '../d10_ethos/types';
import { StrategicDecision } from '../d12_rottweiler/types';
import { ExecutionResult } from '../d1_infantaria/types';

export interface PipelineContext {
    event: SecurityEvent;
    enriched: EnrichedIOC;
    classification: ClassificationResult;
    decision: StrategicDecision;
    execution: ExecutionResult;
    latency_ms?: number;
}

export type FeedbackType = 'POSITIVE_REINFORCEMENT' | 'NEGATIVE_CORRECTION' | 'ANOMALY_FLAG' | 'NEUTRAL';

export interface ReinforcementSignal {
    target_agent: 'D2' | 'D3' | 'D10';
    rule_id?: string;
    adjustment_factor: number; // e.g., +0.1 or -0.5
    reason: string;
}

export interface FeedbackResult {
    feedback_type: FeedbackType;
    signals: ReinforcementSignal[];
    bda_summary: string; // Battle Damage Assessment
    needs_human_review: boolean;
}

export interface LessonLearned {
    decision_id: string;
    action: string;
    outcome: string;
    effectiveness: number; // 0-1
    reinforcement: string;
    timestamp: string;
}
