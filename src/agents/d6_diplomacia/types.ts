import { ComplianceValidationResult } from '../d5_artilharia/types';
import { PredictionResult } from '../d9_attackgraph/types';
import { DetectionResult } from '../d2_sentinela/types';

export enum StrategicImpact {
    LOW = 'Low Business Impact',
    MEDIUM = 'Medium Business Impact',
    HIGH = 'High Business Impact',
    CRITICAL = 'Critical Business Risk'
}

export interface BusinessMetric {
    name: string;
    value: string | number;
    unit?: string;
    trend: 'improving' | 'stable' | 'declining' | 'unknown';
}

export interface ExecutiveReport {
    id: string;
    timestamp: string;
    title: string;
    summary: string;
    impact: StrategicImpact;
    metrics: BusinessMetric[];
    technical_context: {
        detections: DetectionResult[];
        compliance: ComplianceValidationResult[];
        predictions: PredictionResult[];
    };
    recommendations: string[];
}

export interface INarrativeEngine {
    generateSummary(report: ExecutiveReport): string;
    translateImpact(severity: string): StrategicImpact;
}
