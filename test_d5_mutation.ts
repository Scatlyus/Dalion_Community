import { SecurityEvent } from './src/agents/d2_sentinela/types';
import { MutationLab } from './src/agents/d5_artilharia/MutationLab';
import { ComplianceRule, ComplianceFramework } from './src/agents/d5_artilharia/types';
import { strict as assert } from 'assert';

async function testMutationLab() {
    console.log('🧪 Testing D5 Mutation Lab - Sandbox Simulation');

    const lab = new MutationLab();

    // 1. Dataset de teste (Simula histórico de eventos)
    const history: SecurityEvent[] = [
        {
            timestamp: new Date().toISOString(),
            event_id: 'H-001',
            log_source_id: 'SSH',
            source_ip: '10.0.0.1',
            action: 'login',
            status: 'failure',
            severity: 'medium',
            message: 'User xpto@gmail.com failed' // Email leak
        },
        {
            timestamp: new Date().toISOString(),
            event_id: 'H-002',
            log_source_id: 'NGINX',
            source_ip: '10.0.0.2',
            action: 'web',
            status: 'success',
            severity: 'low',
            message: 'GET /public/index.html' // Clean
        }
    ];

    // 2. Nova "Mutação" de Regra (ex: detectando cartões de crédito mockados)
    const cardRule: ComplianceRule = {
        id: 'MOD-PCI-001',
        name: 'Credit Card Leak',
        description: 'Detects credit card patterns in logs.',
        framework: ComplianceFramework.PCI_DSS,
        severity: 'critical',
        check: async (event: SecurityEvent) => {
            return /\d{4}-\d{4}-\d{4}-\d{4}/.test(event.message);
        }
    };

    // 3. Testando a regra mutada contra o histórico
    console.log('\n--- Running Single Rule Mutation Test ---');
    const mutationResult = await lab.testRule(cardRule, [
        ...history,
        {
            timestamp: new Date().toISOString(),
            event_id: 'H-003',
            log_source_id: 'SYSTEM',
            source_ip: '127.0.0.1',
            action: 'log',
            status: 'allowed',
            severity: 'high',
            message: 'Transaction failed for card 1234-5678-9012-3456' // New leak
        }
    ]);

    console.log(`Rule: ${mutationResult.rule_id}`);
    assert.equal(mutationResult.violations_detected, 1);
    assert.equal(mutationResult.total_events, 3);
    console.log(`Violations Detected: ${mutationResult.violations_detected}`);
    console.log(`Pass Rate: ${mutationResult.pass_rate.toFixed(2)}%`);
    mutationResult.details.forEach(d => console.log(`  - ${d}`));

    // 4. Teste de Regressão completa
    console.log('\n--- Running Full Regression Test ---');
    const { total_violations, report } = await lab.runRegression([cardRule], history);
    assert.equal(total_violations, 0);
    assert.equal(report.length, 1);
    console.log(`Total Regression Violations: ${total_violations}`);
    report.forEach(r => console.log(`Rule ${r.rule_id}: Pass Rate ${r.pass_rate}%`));
}

testMutationLab().catch(error => { console.error(error); process.exitCode = 1; });
