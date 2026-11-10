// @ts-nocheck
import * as fs from 'fs';
import * as path from 'path';
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionEspionagem } from './src/agents/d3_espionagem/index';
import { DalionEthos } from './src/agents/d10_ethos/index';
import { DalionRottweiler } from './src/agents/d12_rottweiler/index';
import { DalionInfantaria } from './src/agents/d1_infantaria/index';
import { IoCExtractor } from './src/core/orchestrator/IoCExtractor';
import { DecisionEngine } from './src/core/orchestrator/DecisionEngine';

interface ValidationMetrics {
    total_events: number;
    detections: number;
    true_positives: number;
    false_positives: number;
    false_negatives: number;
    enrichment_cache_hits: number;
    decisions: {
        block: number;
        isolate: number;
        monitor: number;
    };
}

async function runKC7Validation() {
    console.log('=== 🎯 KC7 MODULE 2 VALIDATION ===\n');

    // 1. Load Dataset
    const datasetPath = path.join(__dirname, 'data/kc7_module2/kc7_dataset.json');
    const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf-8'));

    console.log(`📂 Dataset Loaded: ${dataset.length} events\n`);

    // 2. Initialize Agents
    const d2 = new DalionSentinela();
    const d3 = new DalionEspionagem({
        virustotal: { api_key: 'mock', rate_limit: { max_requests: 60000, per_minutes: 1 }, timeout_ms: 1000 },
        abuseipdb: { api_key: 'mock', rate_limit: { max_requests: 86400000, per_day: 1 }, timeout_ms: 1000 },
        cache: { enabled: false, redis_url: 'redis://localhost:6379', ttl_seconds: 3600 },
        conflict_resolution: { strategy: 'most_severe' }
    } as any);
    const d10 = new DalionEthos();
    const d12 = new DalionRottweiler();
    const extractor = new IoCExtractor();
    const decisionEngine = new DecisionEngine();

    // Mock D3 clients to avoid real API calls
    d3.vtClient = {
        getIPReport: async (ip) => ({
            reputation_score: ip === '185.220.101.42' ? -0.9 : 0.5,
            last_analysis_stats: { malicious: ip === '185.220.101.42' ? 45 : 0 }
        }),
        getDomainReport: async (domain) => ({
            reputation_score: domain.includes('badactor') ? -0.95 : 0.3,
            last_analysis_stats: { malicious: domain.includes('badactor') ? 50 : 0 }
        })
    };
    d3.abuseIPDBClient = {
        checkIP: async (ip) => ({
            abuse_confidence_score: ip === '185.220.101.42' ? 95 : 10
        })
    };

    // 3. Process Events
    const metrics: ValidationMetrics = {
        total_events: dataset.length,
        detections: 0,
        true_positives: 0,
        false_positives: 0,
        false_negatives: 0,
        enrichment_cache_hits: 0,
        decisions: { block: 0, isolate: 0, monitor: 0 }
    };

    const knownMaliciousIPs = ['185.220.101.42', '10.0.1.50'];
    const knownMaliciousDomains = ['badactor.ru'];

    for (const [index, event] of dataset.entries()) {
        // Convert Suricata event to SecurityEvent
        const secEvent = {
            event_id: `kc7-${index}`,
            timestamp: event.timestamp,
            action: event.event_type,
            status: 'allowed' as const,
            severity: event.alert?.severity === 1 ? 'critical' as const : 'informational' as const,
            message: event.alert?.signature || `${event.event_type} event`,
            source_ip: event.src_ip,
            destination_ip: event.dest_ip,
            log_source_id: 'kc7-dataset',
            metadata: { ...event, dns: typeof event.dns?.query === 'string' ? { query: [{ rrname: event.dns.query }] } : event.dns }
        };

        // D2: Detection
        const d2Result = await d2.analyze(secEvent);
        if (d2Result.anomaly) {
            metrics.detections++;

            // Check if true positive (malicious IOC detected correctly)
            const isMalicious = knownMaliciousIPs.includes(event.src_ip) ||
                knownMaliciousIPs.includes(event.dest_ip) ||
                (event.dns?.query && knownMaliciousDomains.some(d => event.dns.query.includes(d)));

            if (isMalicious) {
                metrics.true_positives++;
            } else {
                metrics.false_positives++;
            }

            // D3: Enrichment
            const iocs = extractor.extractFromEvent(secEvent).map(ioc => ({ ...ioc, is_anomaly: true }));

            const d3Result = await d3.enrich({ iocs });
            metrics.enrichment_cache_hits += d3Result.summary_report.cache_hits;

            // D10: Classification
            const consolidated = decisionEngine.consolidate(d3Result.enriched_iocs, secEvent);
            const d10Result = await d10.classify(consolidated);

            // D12: Decision
            const decision = d12.decide(d2Result, consolidated, d10Result);
            if (decision.action === 'BLOCK') metrics.decisions.block++;
            else if (decision.action === 'ISOLATE_HOST') metrics.decisions.isolate++;
            else metrics.decisions.monitor++;
        }
    }

    // Calculate false negatives (malicious events not detected)
    const maliciousEventsInDataset = dataset.filter(e =>
        knownMaliciousIPs.includes(e.src_ip) ||
        knownMaliciousIPs.includes(e.dest_ip) ||
        (e.dns?.query && knownMaliciousDomains.some(d => e.dns.query.includes(d)))
    ).length;

    metrics.false_negatives = maliciousEventsInDataset - metrics.true_positives;

    // 4. Generate Report
    console.log('\n=== 📊 VALIDATION RESULTS ===\n');
    console.log(`Total Events Processed: ${metrics.total_events}`);
    console.log(`Detections Triggered:   ${metrics.detections}`);
    console.log(`\n📈 Accuracy Metrics:`);
    console.log(`   True Positives:  ${metrics.true_positives} (Correctly detected threats)`);
    console.log(`   False Positives: ${metrics.false_positives} (Benign flagged as threat)`);
    console.log(`   False Negatives: ${metrics.false_negatives} (Missed threats)`);

    const precision = metrics.true_positives / (metrics.true_positives + metrics.false_positives) || 0;
    const recall = metrics.true_positives / (metrics.true_positives + metrics.false_negatives) || 0;
    const f1 = 2 * (precision * recall) / (precision + recall) || 0;

    console.log(`\n🎯 Performance:`);
    console.log(`   Precision: ${(precision * 100).toFixed(1)}% (Of all alerts, how many were real)`);
    console.log(`   Recall:    ${(recall * 100).toFixed(1)}% (Of all threats, how many we caught)`);
    console.log(`   F1 Score:  ${(f1 * 100).toFixed(1)}%`);

    console.log(`\n🔍 Enrichment:`);
    console.log(`   Cache Hits: ${metrics.enrichment_cache_hits} (Redis effectiveness)`);

    console.log(`\n⚖️ Decisions:`);
    console.log(`   BLOCK:   ${metrics.decisions.block}`);
    console.log(`   ISOLATE: ${metrics.decisions.isolate}`);
    console.log(`   MONITOR: ${metrics.decisions.monitor}`);

    await d3.close();

    return metrics;
}

runKC7Validation().catch(error => { console.error(error); process.exitCode = 1; });
