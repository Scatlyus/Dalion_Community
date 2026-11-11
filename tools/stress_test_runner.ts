/** Measures the ingest process using samples emitted by the process itself. */
import * as fs from 'fs';
import * as readline from 'readline';
import { spawn } from 'child_process';
import { performance } from 'perf_hooks';

type Action = 'ALLOW' | 'MONITOR' | 'BLOCK' | 'QUARANTINE' | 'ISOLATE_HOST';
interface Sample { latency_ms?: number; rss_bytes: number }

export async function runStressTest(inputFile: string) {
    const latencies: number[] = [];
    const memorySamples: number[] = [];
    const decisions: Record<Action, number> = { ALLOW: 0, MONITOR: 0, BLOCK: 0, QUARANTINE: 0, ISOLATE_HOST: 0 };
    const expectedVsActual = { total: 0, matches: 0, mismatches: 0 };
    const started = performance.now();
    const child = spawn(process.execPath, [require.resolve('ts-node/dist/bin.js'), '--transpile-only', 'tools/ingest_suricata_eve.ts', '--file', inputFile, '--strict', '--metrics'], { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stderr.pipe(process.stderr);
    const completion = new Promise<number | null>((resolve, reject) => { child.once('close', resolve); child.once('error', reject); });
    const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    for await (const line of lines) {
        if (line.startsWith('[DALION_METRICS] ')) {
            const sample: Sample = JSON.parse(line.slice('[DALION_METRICS] '.length));
            memorySamples.push(sample.rss_bytes / 1024 / 1024);
            if (sample.latency_ms !== undefined) latencies.push(sample.latency_ms);
        }
        const action = line.match(/\[D12 Decision\] (ALLOW|MONITOR|BLOCK|QUARANTINE|ISOLATE_HOST)/)?.[1] as Action | undefined;
        if (action) decisions[action]++;
        const matched = line.match(/(?:Total Events|Passed|Failed): (\d+)/);
        if (matched) {
            const value = Number(matched[1]);
            if (line.includes('Total Events:')) expectedVsActual.total = value;
            else if (line.includes('Passed:')) expectedVsActual.matches = value;
            else expectedVsActual.mismatches = value;
        }
    }
    const exitCode = await completion;
    if (exitCode !== 0) throw new Error(`Pipeline failed with exit code ${exitCode}`);
    if (!latencies.length || !memorySamples.length) throw new Error('No pipeline measurements received');
    latencies.sort((a, b) => a - b);
    const percentile = (p: number) => latencies[Math.ceil(p * latencies.length) - 1];
    const duration = performance.now() - started;
    return {
        totalEvents: latencies.length,
        duration_ms: duration,
        throughput_eps: latencies.length / duration * 1000,
        latency: { p50: percentile(.5), p95: percentile(.95), p99: percentile(.99), min: latencies[0], max: latencies[latencies.length - 1], mean: latencies.reduce((a, b) => a + b, 0) / latencies.length },
        memory: { start_mb: memorySamples[0], peak_sampled_mb: Math.max(...memorySamples), end_mb: memorySamples[memorySamples.length - 1] },
        decisions, expectedVsActual,
    };
}

async function main() {
    const inputFile = process.argv[2] || 'tools/stress_baseline.json';
    const metrics = await runStressTest(inputFile);
    console.log(JSON.stringify(metrics, null, 2));
    console.log('Memory is RSS sampled at event boundaries; throughput includes process startup.');
    const passed = metrics.latency.p95 < 5000 && metrics.throughput_eps > 50 && metrics.memory.peak_sampled_mb - metrics.memory.start_mb < 200;
    console.log(passed ? 'All performance gates passed.' : 'Performance gates failed.');
    if (process.argv[3]) fs.writeFileSync(process.argv[3], JSON.stringify(metrics, null, 2));
    if (!passed) process.exitCode = 1;
}

if (require.main === module) main().catch(error => { console.error('Stress test failed:', error); process.exitCode = 1; });
