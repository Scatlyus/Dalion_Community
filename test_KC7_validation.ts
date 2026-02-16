import * as fs from 'fs';
import * as path from 'path';
import * as dotenv from 'dotenv';
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionEspionagem } from './src/agents/d3_espionagem/index';
import { DalionEthos } from './src/agents/d10_ethos/index';
import { DalionRottweiler } from './src/agents/d12_rottweiler/index';
import { SecurityEvent } from './src/agents/d2_sentinela/types';

dotenv.config();

interface LabIOC {
    id: string;
    ioc_type: 'IP' | 'domain';
    ioc_value: string;
    label: 'malicious' | 'clean' | 'suspicious';
    context: any;
}

async function runKC7Validation() {
    console.log('=== 🧪 DALION VR01: KC7 EXTERNAL VALIDATION ===\n');

    try {
        // Load Dataset
        const datasetPath = path.join(__dirname, 'data', 'certified_lab_dataset.json');
        if (!fs.existsSync(datasetPath)) {
            throw new Error(`Dataset not found at ${datasetPath}`);
        }
        const dataset: LabIOC[] = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));

        // Initialize Agents
        const d2 = new DalionSentinela();

        const d3 = new DalionEspionagem({
            virustotal: {
                api_key: process.env.VT_API_KEY || '',
                rate_limit: { max_requests: 4, per_minutes: 1 },
                timeout_ms: 15000
            },
            abuseipdb: {
                api_key: process.env.ABUSEIPDB_API_KEY || '',
                rate_limit: { max_requests: 1000, per_day: 1 },
                timeout_ms: 15000
            },
            cache: { enabled: false, redis_url: '', ttl_seconds: 0 },
            conflict_resolution: { strategy: 'most_severe' }
        });

        const d10 = new DalionEthos();
        const d12 = new DalionRottweiler();

        console.log(`📊 Dataset Loaded: ${dataset.length} IOCs`);
        console.log('🔍 Starting Pipeline (D2 -> D3 -> D12)...\n');

        const results: any[] = [];
        const startTime = Date.now();

        for (const item of dataset) {
            console.log(`[${item.id}] Validating ${item.ioc_type}: ${item.ioc_value}...`);

            // 1. D2 - Local Heuristics
            const event: SecurityEvent = {
                timestamp: new Date().toISOString(),
                event_id: `evt-${item.id}`,
                log_source_id: 'LAB_SOURCE',
                source_ip: item.ioc_type === 'IP' ? item.ioc_value : '1.1.1.1',
                action: 'network_connect',
                status: 'allowed',
                severity: 'medium',
                message: `Outbound connection to ${item.ioc_value}. Scenario: ${item.context.scenario}`,
                email_sender: item.ioc_type === 'domain' ? `malware@${item.ioc_value}` : undefined
            };

            const d2Result: any = await d2.analyze(event);

            // 2. D3 - Global Intelligence
            const d3Result: any = await d3.enrich({
                iocs: [{ ioc_type: item.ioc_type, ioc_value: item.ioc_value, is_anomaly: d2Result.anomaly }],
                use_cache: false
            });
            const enrichedIOC = d3Result.enriched_iocs[0];

            // 3. D10 - Taxonomy & Classification
            const d10Result = await d10.classify(enrichedIOC);

            // 4. D12 - Strategic Arbiter
            const decision = d12.decide(d2Result, enrichedIOC, d10Result);

            results.push({
                id: item.id,
                ioc: item.ioc_value,
                label: item.label,
                decision: decision.action,
                reason: decision.reason,
                d2_score: d2Result.anomaly_score,
                d3_score: enrichedIOC.threat_score,
                d3_rep: enrichedIOC.reputation,
                d10_type: d10Result.threat_type
            });

            console.log(`     -> D2: ${d2Result.anomaly_score} | D3: ${enrichedIOC.threat_score} (${enrichedIOC.reputation}) | D10: ${d10Result.threat_type} | D12: ${decision.action}`);
        }

        const duration = (Date.now() - startTime) / 1000;

        // METRICS CALCULATION
        console.log('\n' + '='.repeat(60));
        console.log('📈 VALIDATION METRICS');
        console.log('='.repeat(60));

        let tp = 0; // True Positive (Malicious -> Block/Quarantine)
        let tn = 0; // True Negative (Clean -> Allow)
        let fp = 0; // False Positive (Clean -> Block/Quarantine)
        let fn = 0; // False Negative (Malicious -> Allow)

        results.forEach(r => {
            const blocked = r.decision === 'BLOCK' || r.decision === 'QUARANTINE';

            if (r.label === 'malicious') {
                if (blocked) tp++; else fn++;
            } else if (r.label === 'clean') {
                if (!blocked) tn++; else fp++;
            }
        });

        const accuracy = ((tp + tn) / (tp + tn + fp + fn)) * 100;
        const precision = tp / (tp + fp) || 0;
        const recall = tp / (tp + fn) || 0;

        console.log(`Total Malicious: ${tp + fn}`);
        console.log(`Total Clean: ${tn + fp}`);
        console.log(`True Positives (Blocked): ${tp}`);
        console.log(`True Negatives (Allowed): ${tn}`);
        console.log(`False Positives (Mistakenly Blocked): ${fp}`);
        console.log(`False Negatives (Missed Threat): ${fn}`);
        console.log('\n' + '-'.repeat(30));
        console.log(`ACCURACY: ${accuracy.toFixed(2)}%`);
        console.log(`PRECISION: ${precision.toFixed(2)}`);
        console.log(`RECALL: ${recall.toFixed(2)}`);
        console.log(`TOTAL DURATION: ${duration.toFixed(2)}s`);
        console.log('='.repeat(60));

        await d3.close();
    } catch (err) {
        console.error('❌ Validation Failed:', err);
    }
}

runKC7Validation();
