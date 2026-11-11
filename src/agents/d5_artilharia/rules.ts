import { SecurityEvent } from '../d2_sentinela/types';
import { ComplianceRule, ComplianceFramework } from './types';
import { posix } from 'path';

export const getLGPDRules = (): Map<string, ComplianceRule> => {
    const rules = new Map<string, ComplianceRule>();

    // RL-LGPD-001: Detecção de PII em logs de erro (Email)
    rules.set('RL-LGPD-001', {
        id: 'RL-LGPD-001',
        name: 'PII Leak: Email in Message',
        description: 'Detects clear-text emails in security logs (Potential LGPD violation).',
        framework: ComplianceFramework.LGPD,
        severity: 'high',
        check: async (event: SecurityEvent) => {
            const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
            return emailRegex.test(event.message);
        },
        remediation: 'Anonymize or mask email addresses in log messages before ingestion.'
    });

    // RL-LGPD-002: Acesso a dados sensíveis sem auditoria (Mock)
    rules.set('RL-LGPD-002', {
        id: 'RL-LGPD-002',
        name: 'Unauthorized Sensitive Path Access',
        description: 'Detects access to sensitive directory paths typically containing PII.',
        framework: ComplianceFramework.LGPD,
        severity: 'critical',
        check: async (event: SecurityEvent) => {
            if (!event.file_path) return false;
            const filePath = posix.normalize(event.file_path.replace(/\\/g, '/'));
            const sensitive = ['/etc/passwd', '/etc/shadow'].includes(filePath) ||
                ['/data/customers', '/data/pii'].some(dir => filePath === dir || filePath.startsWith(`${dir}/`));
            const unauthorized = event.metadata?.authorized === false || event.metadata?.authorization === 'denied' || event.action.startsWith('unauthorized_');
            return sensitive && unauthorized;
        },
        remediation: 'Verify authorization for the user and ensure access is logged in a separate audit trail.'
    });

    // RL-LGPD-003: Transferência de dados não criptografada (Status check)
    rules.set('RL-LGPD-003', {
        id: 'RL-LGPD-003',
        name: 'Unencrypted Data Transfer Status',
        description: 'Flags events where status is "allowed" but transfer is noted as unencrypted in metadata.',
        framework: ComplianceFramework.LGPD,
        severity: 'medium',
        check: async (event: SecurityEvent) => {
            return event.status === 'allowed' &&
                event.metadata?.encryption === 'none' &&
                (event.action === 'file_transfer' || event.action === 'network_flow');
        },
        remediation: 'Enforce TLS/SSL for all data transfers involving internal or external flows.'
    });

    return rules;
};
