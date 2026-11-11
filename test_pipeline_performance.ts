// @ts-nocheck
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionEspionagem } from './src/agents/d3_espionagem/index';
import { DalionEthos } from './src/agents/d10_ethos/index';
import { DalionRottweiler } from './src/agents/d12_rottweiler/index';
import { DalionInfantaria } from './src/agents/d1_infantaria/index';
import { DalionThreatIntel } from './src/agents/d8_threatintel/index';
import { SecurityEvent } from './src/agents/d2_sentinela/types';

// Mocks para evitar chamadas de API reais durante stress test
class MockEspionagem extends DalionEspionagem {
    async enrich(params: any): Promise<any> {
        // Simula delay de rede (10-50ms)
        await new Promise(resolve => setTimeout(resolve, 10 + Math.random() * 40));
        return {
            enriched_iocs: params.iocs.map((ioc: any) => ({
                ...ioc,
                tags: Math.random() > 0.8 ? ['malicious', 'botnet'] : ['clean'],
                threat_score: Math.random() > 0.8 ? 85 : 10,
                enrichment: {
                    virustotal: { malicious: 0, suspicious: 0 },
                    whois: { created_date: '2020-01-01' }
                }
            }))
        };
    }
}

class MockThreatIntel extends DalionThreatIntel {
    async lookup(value: string): Promise<any[]> {
        return Math.random() > 0.9 ? [{ source: 'alienvault', tags: ['apt29'], confidence: 90 }] : [];
    }
}

async function runPipelineStress() {
    console.log('=== 🌊 DALION PIPELINE PERFORMANCE TEST ===');
    console.log('Scenario: End-to-End Throughput (D2 -> D12) with 5k events\n');

    // 1. Setup Agents
    const d2 = new DalionSentinela();
    // Force cast config to any to bypass strict type checks for stress test
    const d3 = new MockEspionagem({
        virustotal: { api_key: 'mock', rate_limit: { max_requests: 1000, per_minutes: 1 }, timeout_ms: 1000 },
        abuseipdb: { api_key: 'mock', rate_limit: { max_requests: 1000, per_day: 1 }, timeout_ms: 1000 },
        whois: { enabled: true, rate_limit: { max_requests: 5, per_seconds: 1 } },
        cache: { enabled: false }
    } as any);
    const d8 = new MockThreatIntel({
        alienvault_otx: { api_key: 'mock' },
        abuseipdb: { api_key: 'mock' }
    } as any);
    const d10 = new DalionEthos();
    const d12 = new DalionRottweiler();
    const d1 = new DalionInfantaria({
        auto_execute: false,
        require_approval_for: []
    } as any);

    // 2. Generate Load
    const TOTAL_EVENTS = 5000;
    const events: SecurityEvent[] = Array.from({ length: TOTAL_EVENTS }, (_, i) => ({
        timestamp: new Date().toISOString(),
        event_id: `stress-${i}`,
        log_source_id: 'stress-gen',
        source_ip: `192.168.1.${i % 255}`,
        action: 'login',
        status: (i % 10 === 0 ? 'failure' : 'success') as any, // Cast to avoid TS2367 if type is strict literal
        severity: (i % 50 === 0 ? 'high' : 'low') as any,      // Cast to avoid TS2367 if type is strict literal
        message: 'Stress test synthetic event',
        context: { url: i % 20 === 0 ? 'http://malicious.com' : 'http://google.com' }
    } as any)); // Force cast entire object to avoid other strict checks in test script

    console.log(`🚀 Starting execution of ${TOTAL_EVENTS} events...`);

    // 3. Execution Loop
    const start = performance.now();
    let processed = 0;
    const latencies: number[] = [];

    // Processar em chunks para não estourar o event loop de uma vez só
    const CHUNK_SIZE = 100;
    for (let i = 0; i < events.length; i += CHUNK_SIZE) {
        const chunk = events.slice(i, i + CHUNK_SIZE);
        await Promise.all(chunk.map(async (event) => {
            const t0 = performance.now();

            // D2
            const d2Result = await d2.analyze(event);

            // D3 + D8 (Enrichment)
            // Execute enrichment and classification for every event being measured.
            {
                const d3ResultRaw: any = await d3.enrich({
                    iocs: [{ ioc_type: 'IP', ioc_value: event.source_ip, is_anomaly: d2Result.anomaly, event }],
                    use_cache: false
                });
                const enriched = d3ResultRaw.enriched_iocs[0];
                await d8.lookup(event.source_ip); // Simulando lookup

                // D10
                const d10Result = await d10.classify(enriched);

                // D12
                const decision = d12.decide(d2Result, enriched, d10Result);

                // D1
                if (decision.action !== 'MONITOR') {
                    await d1.respond(decision, event.source_ip);
                }
            }

            const t1 = performance.now();
            latencies.push(t1 - t0);
            processed++;
        }));

        if (i % 1000 === 0 && i > 0) process.stdout.write('.');
    }

    const end = performance.now();
    const duration = (end - start) / 1000; // seconds

    // 4. Analysis
    const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    latencies.sort((a, b) => a - b);
    const p50 = latencies[Math.floor(latencies.length * 0.5)];
    const p95 = latencies[Math.floor(latencies.length * 0.95)];
    const p99 = latencies[Math.floor(latencies.length * 0.99)];
    const eps = TOTAL_EVENTS / duration;

    console.log('\n\n=== 📊 RESULTS ===');
    console.log(`Total Events: ${TOTAL_EVENTS}`);
    console.log(`Duration:     ${duration.toFixed(2)}s`);
    console.log(`Throughput:   ${eps.toFixed(1)} EPS (Events Per Second)`);
    console.log('\n--- Latency ---');
    console.log(`Average:      ${avgLatency.toFixed(2)}ms`);
    console.log(`P50 (Median): ${p50.toFixed(2)}ms`);
    console.log(`P95:          ${p95.toFixed(2)}ms`);
    console.log(`P99:          ${p99.toFixed(2)}ms`);

    // Gap Analysis preliminar
    console.log('\n--- 🔍 GAP ANALYSIS INSIHTS ---');
    if (eps < 100) console.log('⚠️  LOW THROUGHPUT: Pipeline bottleneck detected (likely Mock D3 delay)');
    else console.log('✅ HIGH THROUGHPUT: Pipeline handling load well');

    if (p99 > 500) console.log('⚠️  HIGH LATENCY SPIKES: P99 > 500ms indicates jitter or GC pauses');
    else console.log('✅ STABLE LATENCY: P99 under 500ms');

}

runPipelineStress().catch(error => { console.error(error); process.exitCode = 1; });
