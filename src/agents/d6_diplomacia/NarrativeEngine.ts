import { ExecutiveReport, StrategicImpact, INarrativeEngine } from './types';

export class NarrativeEngine implements INarrativeEngine {
    /**
     * Traduz a severidade técnica em impacto estratégico de negócio.
     */
    translateImpact(severity: string): StrategicImpact {
        switch (severity.toLowerCase()) {
            case 'critical': return StrategicImpact.CRITICAL;
            case 'high': return StrategicImpact.HIGH;
            case 'medium': return StrategicImpact.MEDIUM;
            default: return StrategicImpact.LOW;
        }
    }

    /**
     * Gera uma narrativa executiva baseada no relatório consolidado.
     */
    generateSummary(report: ExecutiveReport): string {
        const detectionCount = report.technical_context.detections.length;
        const complianceIssues = report.technical_context.compliance.filter(c => !c.compliant).length;
        const strongestPrediction = report.technical_context.predictions.filter(p => p.confidence_score > 0.6).reduce<typeof report.technical_context.predictions[number] | undefined>((best, current) => !best || current.confidence_score > best.confidence_score ? current : best, undefined);

        let narrative = `[EXECUTIVE SUMMARY - ${report.title}]\n`;
        narrative += `Status: ${report.impact}.\n\n`;

        if (detectionCount > 0) {
            narrative += `Observamos ${detectionCount} atividades anômalas no perímetro técnico. `;
        } else {
            narrative += `Não foram detectadas anomalias críticas no período. `;
        }

        if (complianceIssues > 0) {
            narrative += `Existem ${complianceIssues} desvios de conformidade (LGPD/NIST) que requerem atenção imediata para evitar sanções regulatórias. `;
        }

        if (strongestPrediction) {
            const next = strongestPrediction.predicted_next_steps.reduce<typeof strongestPrediction.predicted_next_steps[number] | undefined>((best, current) => !best || current.probability > best.probability ? current : best, undefined);
            narrative += `Nossa análise preditiva indica uma alta probabilidade (${(strongestPrediction.confidence_score * 100).toFixed(0)}%) de progressão de ataque para fases de ${next?.phase || 'persistência'}. `;
        }

        narrative += `\n\nRecomendações Estratégicas:\n`;
        report.recommendations.forEach(r => narrative += `- ${r}\n`);

        return narrative;
    }
}
