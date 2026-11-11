import { SecurityEvent } from './src/agents/d2_sentinela/types';
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionArtilharia } from './src/agents/d5_artilharia/index';
import { strict as assert } from 'assert';

async function testIntegratedChain() {
    console.log('🔗 Testing Integrated Chain: D2 (Sentinel) -> D5 (Artillery)');

    const sentinel = new DalionSentinela();
    const artillery = new DalionArtilharia();

    const suspiciousEvent: SecurityEvent = {
        timestamp: new Date().toISOString(),
        event_id: 'INT-001',
        log_source_id: 'WEB-GATEWAY',
        source_ip: '45.133.1.25',
        action: 'sql_injection_attempt',
        status: 'blocked',
        severity: 'high',
        message: 'SQL Injection detected on /api/login?user=admin--'
    };

    console.log('\nStep 1: D2 Sentinel Analysis');
    const d2Result = await sentinel.analyze(suspiciousEvent);
    assert.equal(d2Result.anomaly, true);
    console.log(`Anomaly: ${d2Result.anomaly} | Risk: ${d2Result.risk_level} | Tags: ${d2Result.tags.join(', ')}`);

    console.log('\nStep 2: D5 Artillery Compliance Check');
    const d5Result = await artillery.validate(suspiciousEvent);
    assert.equal(d5Result.compliant, true);
    assert.equal(d5Result.violations.length, 0);
    console.log(`Compliant: ${d5Result.compliant ? '✅ YES' : '❌ NO'}`);
    if (!d5Result.compliant) {
        console.log(`Violations: ${d5Result.violations.map(v => v.id).join(', ')}`);
    }

    console.log('\nChain execution finished. D5 successfully analyzed the output from the same event stream.');
}

testIntegratedChain().catch(error => { console.error(error); process.exitCode = 1; });
