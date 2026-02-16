import { DetectionResult } from '../d2_sentinela/types';
import { EnrichedIOC } from '../d3_espionagem/types';

export type SecurityAction = 'ALLOW' | 'MONITOR' | 'QUARANTINE' | 'BLOCK' | 'ISOLATE_HOST';

export interface StrategicDecision {
    action: SecurityAction;
    reason: string;
    priority: number; // 0..100
    source_signals: {
        d2: {
            anomaly_score: number;
            risk_level: string;
        };
        d3: {
            threat_score: number;
            reputation: string;
            confidence: number;
        };
        d10?: {
            threat_type: string;
            mitre_tactics: string[];
            severity: string;
        };
    };
    timestamp: string;
}

export interface SDEConfig {
    thresholds: {
        critical_risk: number;
        high_threat: number;
        min_confidence: number;
    };
    default_action: SecurityAction;
}
