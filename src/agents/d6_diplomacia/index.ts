/**
 * Dalion D6 Diplomacia - Executive Communication & Stakeholder Management
 *
 * The final agent in the stack. Responsible for translating technical intelligence
 * into business value, risk assessment, and executive reporting.
 */

import { ExecutiveReport, StrategicImpact, BusinessMetric } from './types';
import { NarrativeEngine } from './NarrativeEngine';
import { DetectionResult } from '../d2_sentinela/types';
import { ComplianceValidationResult } from '../d5_artilharia/types';
import { PredictionResult } from '../d9_attackgraph/types';

export class DalionDiplomacia {
    private narrativeEngine: NarrativeEngine;

    constructor() {
        this.narrativeEngine = new NarrativeEngine();
    }

    /**
     * Consolida dados de múltiplos agentes e gera um relatório executivo.
     */
    async generateExecutiveReport(
        detections: DetectionResult[],
        compliance: ComplianceValidationResult[],
        predictions: PredictionResult[]
    ): Promise<ExecutiveReport> {

        const maxSeverity = this.determineMaxSeverity(detections, compliance);
        const impact = this.narrativeEngine.translateImpact(maxSeverity);

        const report: ExecutiveReport = {
            id: `REP-${Date.now()}`,
            timestamp: new Date().toISOString(),
            title: 'Security Posture & Risk Assessment',
            summary: '', // To be filled by Engine
            impact,
            metrics: this.calculateBusinessMetrics(detections, compliance, predictions),
            technical_context: {
                detections,
                compliance,
                predictions
            },
            recommendations: this.generateRecommendations(impact, compliance)
        };

        report.summary = this.narrativeEngine.generateSummary(report);

        return report;
    }

    private determineMaxSeverity(detections: DetectionResult[], compliance: ComplianceValidationResult[]): string {
        let severity = 'low';

        for (const d of detections) {
            if (d.risk_level === 'critical') return 'critical';
            if (d.risk_level === 'high') severity = 'high';
        }

        for (const c of compliance) {
            if (c.violations.some(v => v.severity === 'critical')) return 'critical';
            if (c.violations.some(v => v.severity === 'high')) severity = 'high';
        }

        return severity;
    }

    private calculateBusinessMetrics(
        detections: DetectionResult[],
        compliance: ComplianceValidationResult[],
        predictions: PredictionResult[]
    ): BusinessMetric[] {
        if (compliance.length === 0) return [];
        return [{ name: 'Regulatory Compliance Rate', value: 100 * compliance.filter(c => c.compliant).length / compliance.length, unit: '%', trend: 'unknown' }];
    }

    private generateRecommendations(impact: StrategicImpact, compliance: ComplianceValidationResult[]): string[] {
        const list = ['Maintain vigilant monitoring on core assets.'];

        if (impact === StrategicImpact.CRITICAL || impact === StrategicImpact.HIGH) {
            list.push('Activate Incident Response Team (IRT) for immediate mitigation.');
        }

        if (compliance.some(c => !c.compliant)) {
            list.push('Update privacy masking policies to align with LGPD requirements.');
        }

        return list;
    }
}

export default DalionDiplomacia;
