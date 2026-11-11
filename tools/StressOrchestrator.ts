import { DalionSentinela } from '../src/agents/d2_sentinela/index';
import { DalionArtilharia } from '../src/agents/d5_artilharia/index';
import { DalionAttackGraph } from '../src/agents/d9_attackgraph/index';
import { DalionDiplomacia } from '../src/agents/d6_diplomacia/index';
import { EventGenerator } from './EventGenerator';
import { MITREPhase } from '../src/agents/d9_attackgraph/types';

async function runVerticalStressTest(eventCount: number) {
    console.log(`🚀 STRESS TEST START: ${eventCount} events`);

    const sentinel = new DalionSentinela();
    const artillery = new DalionArtilharia();
    const attackGraph = new DalionAttackGraph();
    const diplomacy = new DalionDiplomacia();
    const generator = new EventGenerator();

    const noise = generator.generateNoise(eventCount);
    const attackerIp = '45.33.22.11';
    const apt = generator.generateAPTSequence(attackerIp);

    // Integramos o ataque no meio do ruído
    const fullDataset = [...noise];
    fullDataset.splice(Math.floor(eventCount / 2), 0, ...apt.map(a => a.event));

    const start = Date.now();
    let totalD2Time = 0;
    let detections: any[] = [];
    let compliance: any[] = [];
    let predictions: any[] = [];

    console.log('Processing stream...');

    for (const event of fullDataset) {
        const stepStart = Date.now();

        // 1. Sentinel Detection (D2)
        const d2 = await sentinel.analyze(event);
        if (d2.anomaly) detections.push(d2);

        // 2. Compliance Artillery (D5)
        const d5 = await artillery.validate(event);
        if (!d5.compliant) compliance.push(d5);

        // 3. Attack Graph Prediction (D9)
        // Só alimentamos o grafo se houver suspeita ou for parte do APT conhecido
        if (d2.anomaly || event.source_ip === attackerIp) {
            const aptEntry = apt.find(a => a.event.event_id === event.event_id);
            await attackGraph.addEvent(event, aptEntry?.phase ?? MITREPhase.UNKNOWN);
            const pred = await attackGraph.getPredictions(event.source_ip);
            predictions.push(pred);
        }

        totalD2Time += (Date.now() - stepStart);
    }

    const end = Date.now();
    const totalDuration = end - start;

    console.log('\n--- METRICS ---');
    console.log(`Total Time: ${totalDuration}ms`);
    console.log(`Avg Latency per Event: ${(totalD2Time / fullDataset.length).toFixed(2)}ms`);
    console.log(`Events per Second: ${Math.round((fullDataset.length / totalDuration) * 1000)}`);
    console.log(`Anomalies Detected: ${detections.length}`);
    console.log(`Compliance Violations: ${compliance.length}`);
    console.log(`Predictions Generated: ${predictions.length}`);

    console.log('\n--- FINAL EXECUTIVE REPORT (D6) ---');
    const report = await diplomacy.generateExecutiveReport(
        detections.slice(-10), // Report focus on last issues
        compliance.slice(-10),
        predictions.slice(-1)
    );
    console.log(report.summary);
}

const count = parseInt(process.argv[2]) || 1000;
runVerticalStressTest(count).catch(error => { console.error(error); process.exitCode = 1; });
