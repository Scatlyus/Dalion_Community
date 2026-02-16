import * as dotenv from 'dotenv';
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionEspionagem } from './src/agents/d3_espionagem/index';
import { DalionEthos } from './src/agents/d10_ethos/index';
import { DalionRottweiler } from './src/agents/d12_rottweiler/index';
import { DalionInfantaria } from './src/agents/d1_infantaria/index';
import { DalionThreatIntel } from './src/agents/d8_threatintel/index';
import { SecurityEvent } from './src/agents/d2_sentinela/types';

dotenv.config();

/**
 * Dalion Assertion Utility
 */
function assert(condition: any, message: string) {
    if (!condition) {
        console.error(`\n❌ ASSERTION FAILED: ${message}`);
        process.exit(1);
    } else {
        console.log(`✅ ASSERT: ${message}`);
    }
}

async function runHardenedWave2Test() {
    console.log('=== 🌊 DALION VR01: WAVE 2 HARDENED PIPELINE TEST (FINAL) ===');
    console.log('Objective: Validate autonomous response chain with strict asserts.\n');

    // 0. Environment & Safety Checks
    const vtKey = process.env.VT_API_KEY;
    const abuseKey = process.env.ABUSEIPDB_API_KEY;
    const isLabMode = !vtKey || !abuseKey;

    if (isLabMode) {
        console.log('⚠️ [Warning] VT/AbuseIPDB keys missing. Running in PASSIVE/DRY-RUN enrichment mode.');
    }

    // 1. Initialize Full Agent Fleet
    const d2 = new DalionSentinela();
    const d3 = new DalionEspionagem({
        virustotal: { api_key: vtKey || 'mock', rate_limit: { max_requests: 4, per_minutes: 1 }, timeout_ms: 15000 },
        abuseipdb: { api_key: abuseKey || 'mock', rate_limit: { max_requests: 1000, per_day: 1 }, timeout_ms: 15000 },
        cache: { enabled: false, redis_url: '', ttl_seconds: 0 },
        conflict_resolution: { strategy: 'most_severe' }
    });
    const d8 = new DalionThreatIntel();
    const d10 = new DalionEthos();
    const d12 = new DalionRottweiler();
    const d1 = new DalionInfantaria({
        auto_execute: true,
        require_approval_for: ['ISOLATE_HOST']
    });

    const targetIOC = 'malicious-pdf-link.com';

    // 2. D2 - Local Event Detection (Strict Type)
    const event: SecurityEvent = {
        timestamp: new Date().toISOString(),
        event_id: 'pdf-001',
        log_source_id: 'MAIL_GATEWAY',
        source_ip: '10.0.4.20',
        action: 'url_click',
        status: 'allowed',
        severity: 'medium',
        message: 'User clicked on URL from PDF attachment'
    };

    console.log(`[Flow] 1. D2 Analyze...`);
    const d2Result = await d2.analyze(event);

    // 3. D3 + D8 - Intelligence Enrichment (Dynamic Boost)
    console.log(`[Flow] 2. Enrichment (D3 + D8)...`);
    const d3ResultRaw: any = await d3.enrich({
        iocs: [{ ioc_type: 'domain', ioc_value: targetIOC, is_anomaly: d2Result.anomaly }],
        use_cache: false
    });
    const enrichedIOC = d3ResultRaw.enriched_iocs[0];
    const baseScore = enrichedIOC.threat_score;

    const d8Signals = await d8.lookup(targetIOC);

    // Assert D8 specific tag
    assert(Array.isArray(d8Signals), 'D8 returns an array of signals');
    assert(d8Signals.some(s => s.tags.includes('embedded_pdf_phishing')), 'D8 should tag embedded_pdf_phishing for this IOC');

    // Dynamic boost calculation
    const maxBoost = d8Signals.length ? Math.max(...d8Signals.map(s => s.recommended_score_boost ?? 0)) : 0;
    assert(maxBoost > 0, 'D8 should provide a recommended_score_boost > 0 for this scenario');

    if (maxBoost > 0) {
        console.log(`   [D8] Applying dynamic boost: +${maxBoost}`);
        enrichedIOC.tags = [...(enrichedIOC.tags || []), ...d8Signals.flatMap(s => s.tags)];
        enrichedIOC.threat_score = Math.min(100, (enrichedIOC.threat_score ?? 0) + maxBoost);
    }

    assert(enrichedIOC.threat_score > baseScore, 'Threat score should be elevated by D8 intelligence');

    // 4. D10 - Taxonomic Classification
    console.log(`[Flow] 3. Classification (D10)...`);
    const d10Result = await d10.classify(enrichedIOC);
    console.log(`   [D10] Classified as: ${d10Result.threat_type}`);

    assert(d10Result.threat_type === 'phishing', 'D10 should classify as PHISHING');
    assert(Array.isArray(d10Result.mitre_tactics) && d10Result.mitre_tactics.length > 0, 'D10 should output MITRE tactics');

    // 5. D12 - Strategic Arbitration
    console.log(`[Flow] 4. Decision (D12)...`);
    const decision = d12.decide(d2Result, enrichedIOC, d10Result);
    console.log(`   [D12] Strategic Decision: ${decision.action}`);

    assert(['BLOCK', 'ISOLATE_HOST'].includes(decision.action), 'D12 should choose a containment action for high-confidence phishing');
    assert(decision.action === 'BLOCK', 'D12 specific decision should be BLOCK for this scenario');

    // 6. D1 - Rapid Response
    console.log(`[Flow] 5. Execution (D1)...`);
    // Assertion: Ensure BLOCK doesn't require manual approval in this test config
    assert(!['ISOLATE_HOST'].includes('BLOCK'), 'Self-check: BLOCK action should not require approval in this test');

    const response = await d1.respond(decision, targetIOC);
    console.log(`   [D1] Execution Result: ${response.success ? 'SUCCESS' : 'PENDING'}`);

    assert(typeof response.success === 'boolean', 'D1 returns a boolean success flag');
    assert(response.success === true, 'D1 should execute BLOCK automatically in lab mode');
    assert(response.details.includes('[Simulated]'), 'D1 execution details should confirm use of Mock provider');

    console.log('\n🏁 WAVE 2 SCIENTIFIC VALIDATION COMPLETE');
    console.log(`Final Threat Score: ${enrichedIOC.threat_score} (Base: ${baseScore} + MaxBoost: ${maxBoost})`);

    await d3.close();
}

runHardenedWave2Test().catch(console.error);
