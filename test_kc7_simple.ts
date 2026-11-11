import * as fs from 'fs';
import * as path from 'path';
import { DalionSentinela } from './src/agents/d2_sentinela/index';

interface ValidationMetrics {
    total_events: number;
    detections: number;
    true_positives: number;
    false_positives: number;
    false_negatives: number;
}

async function runSimplifiedKC7Validation() {
    console.log('=== 🎯 KC7 MODULE 2 - D2 SENTINELA VALIDATION ===\n');

    // 1. Load Dataset
    const datasetPath = path.join(__dirname, 'data/kc7_module2/kc7_dataset.json');
    const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf-8'));

    console.log(`📂 Dataset Loaded: ${dataset.length} events\n`);

    // 2. Initialize D2 Sentinela
    const d2 = new DalionSentinela();

    // 3. Define Ground Truth
    const knownMaliciousIPs = ['185.220.101.42', '10.0.1.50'];
    const knownMaliciousDomains = ['badactor.ru', 'data-exfil-tunnel'];

    const metrics: ValidationMetrics = {
        total_events: dataset.length,
        detections: 0,
        true_positives: 0,
        false_positives: 0,
        false_negatives: 0
    };

    // 4. Process Events
    for (const event of dataset) {
        // Convert Suricata event to SecurityEvent
        const secEvent = {
            event_id: `kc7-${Date.now()}-${Math.random()}`,
            timestamp: event.timestamp,
            action: event.event_type,
            status: 'allowed' as const,
            severity: event.alert?.severity === 1 ? 'critical' as const : 'informational' as const,
            message: event.alert?.signature || `${event.event_type} event`,
            source_ip: event.src_ip,
            destination_ip: event.dest_ip,
            log_source_id: 'kc7-dataset',
            metadata: event,
            context: { domain: typeof event.dns?.query === 'string' ? event.dns.query : event.dns?.query?.[0]?.rrname }
        };

        // Check if event is malicious (ground truth)
        const isMalicious = knownMaliciousIPs.includes(event.src_ip) ||
            knownMaliciousIPs.includes(event.dest_ip) ||
            (event.dns?.query && knownMaliciousDomains.some(d => event.dns.query.includes(d)));

        // D2: Detection
        const d2Result = await d2.analyze(secEvent);

        if (d2Result.anomaly === true) {
            metrics.detections++;

            if (isMalicious) {
                metrics.true_positives++;
            } else {
                metrics.false_positives++;
            }
        } else if (isMalicious) {
            // Missed detection (false negative)
            metrics.false_negatives++;
        }
    }

    // 5. Generate Report
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

    console.log(`\n📝 Analysis:`);
    if (precision >= 0.7 && recall >= 0.7) {
        console.log(`   ✅ PASS: D2 demonstrates good detection capability`);
    } else if (precision < 0.5 || recall < 0.5) {
        console.log(`   ❌ FAIL: D2 needs tuning (high false positive/negative rate)`);
        process.exitCode = 1;
    } else {
        console.log(`   ⚠️  MARGINAL: D2 is functional but could benefit from rule refinement`);
    }

    return metrics;
}

runSimplifiedKC7Validation().catch(error => { console.error(error); process.exitCode = 1; });
