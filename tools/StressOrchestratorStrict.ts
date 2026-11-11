import { DalionSentinela } from '../src/agents/d2_sentinela/index';
import { DalionArtilharia } from '../src/agents/d5_artilharia/index';
import { DalionAttackGraph } from '../src/agents/d9_attackgraph/index';
import { MITREPhase } from '../src/agents/d9_attackgraph/types';
import { EventGenerator } from './EventGenerator';
import { performance } from 'perf_hooks';

async function runStrictStressTest(eventCount: number) {
    console.log(`🛰️ [ATLAS] STRICT STRESS TEST: ${eventCount} events`);

    const sentinel = new DalionSentinela();
    const artillery = new DalionArtilharia();
    const attackGraph = new DalionAttackGraph();
    const generator = new EventGenerator();

    const dataset = generator.generateNoise(eventCount);

    let stats = {
        sentinel: 0,
        artillery: 0,
        attackGraph: 0,
        total: 0
    };

    const start = performance.now();

    for (const event of dataset) {
        // 1. D2 Sentinel (Forced)
        const s1 = performance.now();
        await sentinel.analyze(event);
        stats.sentinel += (performance.now() - s1);

        // 2. D5 Artillery (Forced)
        const s2 = performance.now();
        await artillery.validate(event);
        stats.artillery += (performance.now() - s2);

        // 3. D9 AttackGraph (Forced + Predict)
        // Usamos uma fase fixa para simular carga real de grafo
        const s3 = performance.now();
        await attackGraph.addEvent(event, MITREPhase.DISCOVERY);
        await attackGraph.getPredictions(event.source_ip);
        stats.attackGraph += (performance.now() - s3);
    }

    const end = performance.now();
    const totalDuration = end - start;

    console.log('\n--- ATLAS AUDIT METRICS (STRICT PATH) ---');
    console.log(`Total Duration: ${totalDuration}ms`);
    console.log(`Throughput: ${Math.round((eventCount / totalDuration) * 1000)} EPS`);
    console.log(`\nLatency Breakdown (Avg):`);
    console.log(`├─ D2 Sentinel:    ${(stats.sentinel / eventCount).toFixed(4)}ms`);
    console.log(`├─ D5 Artillery:   ${(stats.artillery / eventCount).toFixed(4)}ms`);
    console.log(`└─ D9 AttackGraph: ${(stats.attackGraph / eventCount).toFixed(4)}ms`);
    console.log(`\nFull Pipeline:    ${((stats.sentinel + stats.artillery + stats.attackGraph) / eventCount).toFixed(4)}ms`);
}

const count = parseInt(process.argv[2]) || 1000;
runStrictStressTest(count).catch(error => { console.error(error); process.exitCode = 1; });
