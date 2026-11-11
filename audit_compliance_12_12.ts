import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionArtilharia } from './src/agents/d5_artilharia/index';
import { DalionAttackGraph } from './src/agents/d9_attackgraph/index';
import { DalionDiplomacia } from './src/agents/d6_diplomacia/index';
import { MITREPhase } from './src/agents/d9_attackgraph/types';
import { SecurityEvent } from './src/agents/d2_sentinela/types';
import { strict as assert } from 'assert';
import { StrategicImpact } from './src/agents/d6_diplomacia/types';

async function runFinalAtlasAudit() {
    console.log('╔══════════════════════════════════════════════╗');
    console.log('║  🛡️ DALION FINAL INTEGRITY AUDIT (12/12)     ║');
    console.log('╚══════════════════════════════════════════════╝');

    const sentinel = new DalionSentinela();
    const artillery = new DalionArtilharia();
    const attackGraph = new DalionAttackGraph();
    const diplomacy = new DalionDiplomacia();

    const testEvent: SecurityEvent = {
        timestamp: new Date().toISOString(),
        event_id: 'AUDIT-X-001',
        log_source_id: 'CRITICAL-APP',
        source_ip: '77.88.99.100',
        action: 'unauthorized_db_access',
        status: 'failure',
        severity: 'critical',
        message: 'Suspicious SQL access by root@hack.com on /data/pii',
        file_path: '/data/pii/customers.db'
    };

    console.log('\n[PHASE 1] DETECTOR (D2) ...');
    const d2 = await sentinel.analyze(testEvent);
    assert.equal(d2.anomaly, true, 'D2 must detect the anomaly');
    console.log(`> D2 Result: ${d2.anomaly ? '🚩 ANOMALY' : '✅ CLEAN'} (Score: ${d2.anomaly_score})`);

    console.log('\n[PHASE 2] COMPLIANCE (D5) ...');
    const d5 = await artillery.validate(testEvent);
    assert.equal(d5.compliant, false, 'D5 must detect compliance violations');
    assert.deepEqual(d5.violations.map(v => v.id).sort(), ['RL-LGPD-001', 'RL-LGPD-002']);
    console.log(`> D5 Result: ${d5.compliant ? '✅ COMPLIANT' : '🚩 VIOLATION'} (${d5.violations.map(v => v.id).join(', ')})`);

    console.log('\n[PHASE 3] ATTACK GRAPH (D9) ...');
    await attackGraph.addEvent(testEvent, MITREPhase.INITIAL_ACCESS);
    const d9 = await attackGraph.getPredictions(testEvent.source_ip);
    assert.equal(d9.current_phase, MITREPhase.INITIAL_ACCESS);
    assert.ok(d9.predicted_next_steps.length > 0);
    console.log(`> D9 Prediction: Next probable phase is ${d9.predicted_next_steps[0]?.phase} (${(d9.confidence_score * 100).toFixed(0)}%)`);

    console.log('\n[PHASE 4] DIPLOMACY (D6) ...');
    const d6 = await diplomacy.generateExecutiveReport([d2], [d5], [d9]);
    assert.equal(d6.impact, StrategicImpact.CRITICAL);
    assert.ok(d6.summary.includes('desvios de conformidade'));
    console.log('------------------------------------------------');
    console.log(d6.summary);
    console.log('------------------------------------------------');

    console.log('\n✅ VERDITO: Todos os agentes CORE estão operacionais e interligados.');
}

runFinalAtlasAudit().catch(error => { console.error(error); process.exitCode = 1; });
