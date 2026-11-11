import { SecurityEvent } from './src/agents/d2_sentinela/types';
import { DalionAttackGraph } from './src/agents/d9_attackgraph/index';
import { MITREPhase } from './src/agents/d9_attackgraph/types';
import { strict as assert } from 'assert';

async function testD9() {
    console.log('🧪 Testing D9 AttackGraph - Predictive Defense Engine');

    const d9 = new DalionAttackGraph();
    const attackerIp = '10.0.0.66';

    const events: Array<{ event: SecurityEvent, phase: MITREPhase }> = [
        {
            event: {
                timestamp: new Date().toISOString(),
                event_id: 'PH-001',
                log_source_id: 'EMAIL-SEC',
                source_ip: attackerIp,
                action: 'phishing_link_click',
                status: 'success',
                severity: 'high',
                message: 'User clicked on bit.ly/malicious-link'
            },
            phase: MITREPhase.INITIAL_ACCESS
        },
        {
            event: {
                timestamp: new Date().toISOString(),
                event_id: 'EX-001',
                log_source_id: 'ENDPOINT-AGENT',
                source_ip: attackerIp,
                action: 'shell_execution',
                status: 'success',
                severity: 'critical',
                message: 'cmd.exe executed with suspicious arguments'
            },
            phase: MITREPhase.EXECUTION
        }
    ];

    console.log('\n--- Step 1: Ingesting Initial Phases ---');
    for (const entry of events) {
        console.log(`Ingesting phase: ${entry.phase}`);
        await d9.addEvent(entry.event, entry.phase);
    }

    console.log('\n--- Step 2: Requesting Predictions ---');
    const predictions = await d9.getPredictions(attackerIp);
    assert.equal(predictions.current_phase, MITREPhase.EXECUTION);
    assert.equal(predictions.predicted_next_steps[0].phase, MITREPhase.PERSISTENCE);

    console.log(`Current Phase Detected: ${predictions.current_phase}`);
    console.log(`Confidence Score: ${(predictions.confidence_score * 100).toFixed(2)}%`);

    console.log('\nPotential Next Steps:');
    predictions.predicted_next_steps.forEach((p, i) => {
        console.log(`${i + 1}. [${(p.probability * 100).toFixed(0)}%] ${p.phase} -> ${p.description}`);
    });

    console.log('\n--- Step 3: Graph Topology ---');
    const graph = d9.getGraph(attackerIp);
    assert.equal(graph.nodes.length, 2);
    assert.equal(graph.edges.length, 1);
    console.log(`Nodes observed: ${graph.nodes.length}`);
    console.log(`Transitions (edges) established: ${graph.edges.length}`);
}

testD9().catch(error => { console.error(error); process.exitCode = 1; });
