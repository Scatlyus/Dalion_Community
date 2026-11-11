import { SecurityEvent } from './src/agents/d2_sentinela/types';
import { DalionArtilharia } from './src/agents/d5_artilharia/index';
import { strict as assert } from 'assert';

async function testD5() {
    console.log('🧪 Testing D5 Artilharia - Compliance Engine');

    const d5 = new DalionArtilharia();

    const events: SecurityEvent[] = [
        {
            timestamp: new Date().toISOString(),
            event_id: 'EVT-001',
            log_source_id: 'SSH',
            source_ip: '10.0.0.1',
            action: 'login',
            status: 'failure',
            severity: 'medium',
            message: 'Failed login for user admin@empresa.com.br' // Violates RL-LGPD-001
        },
        {
            timestamp: new Date().toISOString(),
            event_id: 'EVT-002',
            log_source_id: 'SURICATA',
            source_ip: '192.168.1.50',
            action: 'file_transfer',
            status: 'allowed',
            severity: 'low',
            message: 'Transferring database backup',
            metadata: { encryption: 'none' } // Violates RL-LGPD-003
        },
        {
            timestamp: new Date().toISOString(),
            event_id: 'EVT-003',
            log_source_id: 'NGINX',
            source_ip: '172.16.0.10',
            action: 'web_access',
            status: 'success',
            severity: 'informational',
            message: 'GET /index.html' // Clean event
        }
    ];

    const expected = [['RL-LGPD-001'], ['RL-LGPD-003'], []];
    for (const [index, event] of events.entries()) {
        const result = await d5.validate(event);
        assert.deepEqual(result.violations.map(v => v.id), expected[index]);
        console.log(`\n--- Event ${event.event_id} ---`);
        console.log(`Message: ${event.message}`);
        console.log(`Compliant: ${result.compliant ? '✅ YES' : '❌ NO'}`);
        if (!result.compliant) {
            console.log(`Violations: ${result.violations.map(v => v.name).join(', ')}`);
            result.violations.forEach(v => console.log(`  - [${v.framework}] ${v.id}: ${v.remediation}`));
        }
    }
}

testD5().catch(error => { console.error(error); process.exitCode = 1; });
