import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { SecurityEvent } from './src/agents/d2_sentinela/types';
import { performance } from 'perf_hooks';

/**
 * Dalion D2 - Real-World Stress & Concurrency Auditor
 * Simulates high concurrency to measure Event Loop lag and actual throughout.
 */

async function runStressTest() {
    const sentinela = new DalionSentinela();
    const CONCURRENCY = 100; // 100 "users" or threads at same time
    const TOTAL_REQUESTS = 10000;
    const sameIP = '1.1.1.1';

    console.log(`=== 🛡️ DALION D2 AUDITOR: CONCURRENCY STRESS TEST ===`);
    console.log(`Config: ${CONCURRENCY} concurrent workers | ${TOTAL_REQUESTS} total requests\n`);

    const samples: number[] = [];
    let processed = 0;

    const worker = async () => {
        while (processed < TOTAL_REQUESTS) {
            processed++;
            const start = performance.now();

            await sentinela.analyze({
                timestamp: new Date().toISOString(),
                event_id: `stress_${processed}`,
                log_source_id: 'stress_test',
                source_ip: sameIP,
                action: 'login',
                status: 'failure',
                severity: 'medium',
                message: 'stress test message containing ransomware and exploit terms to trigger rules'
            });

            const end = performance.now();
            samples.push(end - start);
        }
    };

    const startTime = performance.now();

    // Launch concurrent workers
    const workers = Array(CONCURRENCY).fill(null).map(() => worker());
    await Promise.all(workers);

    const endTime = performance.now();
    const totalDuration = endTime - startTime;

    // Statistics Calculation
    samples.sort((a, b) => a - b);
    const avg = samples.reduce((a, b) => a + b, 0) / samples.length;
    const p95 = samples[Math.floor(samples.length * 0.95)];
    const p99 = samples[Math.floor(samples.length * 0.99)];
    const throughput = (TOTAL_REQUESTS / totalDuration) * 1000;

    // Integrity Check (Sample Result)
    const testProbe = await sentinela.analyze({
        timestamp: new Date().toISOString(),
        event_id: 'probe',
        log_source_id: 'audit',
        source_ip: '185.123.45.67', // Conhecido Malicioso
        action: 'login',
        status: 'failure',
        severity: 'high',
        message: 'testing malware string'
    });

    console.log(`--- INTEGRITY AUDIT ---`);
    console.log(`Probe Result: ${testProbe.anomaly ? '🚨 ANOMALY' : '⚪ OK'} | Score: ${testProbe.anomaly_score}`);
    console.log(`Rules Processed: ${testProbe.rules_processed}`);
    console.log(`Tags Triggered: ${testProbe.tags.join(', ')}`);
    console.log(`\n--- RESULTS (Cold Data) ---`);
    console.log(`Total Duration: ${totalDuration.toFixed(2)}ms`);
    console.log(`Throughput: ${throughput.toFixed(0)} req/sec`);
    console.log(`Latency Avg: ${avg.toFixed(3)}ms`);
    console.log(`Latency P95: ${p95.toFixed(3)}ms`);
    console.log(`Latency P99: ${p99.toFixed(3)}ms`);

    // Memory Audit
    const mem = process.memoryUsage();
    console.log(`\n--- MEMORY AUDIT ---`);
    console.log(`Heap Used: ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB`);
    console.log(`RSS: ${(mem.rss / 1024 / 1024).toFixed(2)} MB`);

    if (p99 > 10) {
        console.log(`\n⚠️ ADVERTÊNCIA: Latência P99 (${p99.toFixed(2)}ms) acima do ideal para motor em memória.`);
    } else {
        console.log(`\n✅ EFICIÊNCIA CONFIRMADA: Latência estável sob concorrência.`);
    }
}

runStressTest().catch(console.error);
