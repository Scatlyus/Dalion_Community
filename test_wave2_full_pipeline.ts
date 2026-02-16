import * as dotenv from 'dotenv';
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionEspionagem } from './src/agents/d3_espionagem/index';
import { DalionEthos } from './src/agents/d10_ethos/index';
import { DalionRottweiler } from './src/agents/d12_rottweiler/index';
import { DalionInfantaria } from './src/agents/d1_infantaria/index';
import { DalionThreatIntel } from './src/agents/d8_threatintel/index';

dotenv.config();

async function runWave2Test() {
    console.log('=== 🌊 DALION VR01: WAVE 2 FULL PIPELINE TEST ===');
    console.log('Scenario: Complex Phishing via Embedded PDF Hook\n');

    // 0. Initialize Full Agent Fleet
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
    const d8 = new DalionThreatIntel();
    const d10 = new DalionEthos();
    const d12 = new DalionRottweiler();
    const d1 = new DalionInfantaria({
        auto_execute: true,
        require_approval_for: ['ISOLATE_HOST'] // Proteção contra contenção acidental crítica
    });

    const targetIOC = 'malicious-pdf-link.com';

    // 1. D2 - Local Event Detection
    console.log(`[Flow] 1. D2 Sentinela monitoring activity for ${targetIOC}...`);
    const event = {
        timestamp: new Date().toISOString(),
        event_id: 'pdf-001',
        log_source_id: 'MAIL_GATEWAY',
        source_ip: '10.0.4.20',
        action: 'url_click',
        status: 'allowed',
        severity: 'medium',
        message: 'User clicked on URL from PDF attachment',
        context: { url: targetIOC }
    };
    const d2Result = await d2.analyze(event as any);

    // 2. D3 + D8 - Intelligence Enrichment
    console.log(`[Flow] 2. D3 Espionagem & D8 ThreatIntel gathering context...`);
    const d3ResultRaw: any = await d3.enrich({
        iocs: [{ ioc_type: 'domain', ioc_value: targetIOC, is_anomaly: d2Result.anomaly }],
        use_cache: false
    });
    const enrichedIOC = d3ResultRaw.enriched_iocs[0];

    // Merge D8 Wisdom into the enriched object
    const d8Signals = await d8.lookup(targetIOC);
    if (d8Signals.length > 0) {
        console.log(`   [D8] Found ${d8Signals.length} signals in ThreatIntel Hub!`);
        enrichedIOC.tags = [...(enrichedIOC.tags || []), ...d8Signals.flatMap(s => s.tags)];
        enrichedIOC.threat_score = Math.max(enrichedIOC.threat_score, 85); // D8 elevates suspicion
    }

    // 3. D10 - Taxonomic Classification
    console.log(`[Flow] 3. D10 Ethos classifying threat taxonomy...`);
    const d10Result = await d10.classify(enrichedIOC);
    console.log(`   [D10] Classification: ${d10Result.threat_type} | MITRE: ${d10Result.mitre_tactics.join(', ')}`);

    // 4. D12 - Strategic Arbitration
    console.log(`[Flow] 4. D12 Rottweiler deciding on response...`);
    const decision = d12.decide(d2Result, enrichedIOC, d10Result);
    console.log(`   [D12] DECISION: ${decision.action} | Reason: ${decision.reason}`);

    // 5. D1 - Rapid Response
    console.log(`[Flow] 5. D1 Infantaria deploying counter-measures...`);
    const response = await d1.respond(decision, targetIOC);

    console.log('\n=== PIPELINE EXECUTION SUMMARY ===');
    console.log(`Final Action Status: ${response.success ? '✅ SUCCESS' : '⚠️ PENDING/FAILED'}`);
    console.log(`Execution Details: ${response.details}`);
    console.log(`D12 Risk Priority: ${decision.priority}`);

    await d3.close();
}

runWave2Test().catch(console.error);
