import { SecurityEvent } from '../d2_sentinela/types';

export enum ComplianceFramework {
    LGPD = 'LGPD',
    GDPR = 'GDPR',
    NIST = 'NIST',
    PCI_DSS = 'PCI-DSS'
}

export interface ComplianceRule {
    id: string;
    name: string;
    description: string;
    framework: ComplianceFramework;
    severity: 'low' | 'medium' | 'high' | 'critical';
    check: (event: SecurityEvent) => Promise<boolean>;
    remediation?: string;
}

export interface ComplianceValidationResult {
    compliant: boolean;
    violations: ComplianceRule[];
    timestamp: string;
    summary: string;
}

export interface IComplianceEngine {
    validate(event: SecurityEvent): Promise<ComplianceValidationResult>;
    addRule(rule: ComplianceRule): void;
    removeRule(ruleId: string): void;
}
