import { SecurityEvent } from '../d2_sentinela/types';
import { ComplianceRule, ComplianceValidationResult } from './types';

export interface MutationTestResult {
    rule_id: string;
    total_events: number;
    violations_detected: number;
    pass_rate: number;
    avg_latency_ms: number;
    details: string[];
}

export class MutationLab {
    /**
     * Testa uma regra isolada contra um conjunto de eventos (Dataset de Teste).
     */
    async testRule(rule: ComplianceRule, dataset: SecurityEvent[]): Promise<MutationTestResult> {
        let violations = 0;
        const details: string[] = [];
        const start = Date.now();

        for (const event of dataset) {
            const isViolation = await rule.check(event);
            if (isViolation) {
                violations++;
                details.push(`Violation ${violations} detected`);
            }
        }

        const end = Date.now();
        const total = dataset.length;

        return {
            rule_id: rule.id,
            total_events: total,
            violations_detected: violations,
            pass_rate: total > 0 ? ((total - violations) / total) * 100 : 100,
            avg_latency_ms: total > 0 ? (end - start) / total : 0,
            details
        };
    }

    /**
     * Executa testes de regressão: valida um novo conjunto de regras contra um histórico conhecido.
     */
    async runRegression(rules: ComplianceRule[], history: SecurityEvent[]): Promise<{ total_violations: number, report: MutationTestResult[] }> {
        const report: MutationTestResult[] = [];
        let totalViolations = 0;

        for (const rule of rules) {
            const result = await this.testRule(rule, history);
            report.push(result);
            totalViolations += result.violations_detected;
        }

        return {
            total_violations: totalViolations,
            report
        };
    }
}
