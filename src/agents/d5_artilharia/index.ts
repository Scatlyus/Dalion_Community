/**
 * Dalion D5 Artilharia - Compliance & Policy Enforcement Engine
 *
 * Responsible for verifying security events against regulatory frameworks (LGPD, NIST, etc).
 */

import { SecurityEvent } from '../d2_sentinela/types';
import { ComplianceRule, ComplianceValidationResult, IComplianceEngine } from './types';
import { getLGPDRules } from './rules';

export class DalionArtilharia implements IComplianceEngine {
    private rules: Map<string, ComplianceRule>;

    constructor() {
        this.rules = new Map<string, ComplianceRule>();
        this.initializeRules();
    }

    private initializeRules() {
        const lgpdRules = getLGPDRules();
        lgpdRules.forEach((rule, id) => this.rules.set(id, rule));
    }

    /**
     * Valida um evento individual contra todas as regras carregadas.
     */
    async validate(event: SecurityEvent): Promise<ComplianceValidationResult> {
        const violations: ComplianceRule[] = [];

        for (const rule of this.rules.values()) {
            if (await rule.check(event)) {
                violations.push(rule);
            }
        }

        const compliant = violations.length === 0;

        return {
            compliant,
            violations,
            timestamp: new Date().toISOString(),
            summary: compliant
                ? 'Event is compliant with all active frameworks.'
                : `Detected ${violations.length} compliance violations: ${violations.map(v => v.id).join(', ')}`
        };
    }

    addRule(rule: ComplianceRule): void {
        this.rules.set(rule.id, rule);
    }

    removeRule(ruleId: string): void {
        this.rules.delete(ruleId);
    }
}

export default DalionArtilharia;
