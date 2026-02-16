import { DalionRottweiler } from './src/agents/d12_rottweiler/index';
import { DetectionResult } from './src/agents/d2_sentinela/types';
import { EnrichedIOC } from './src/agents/d3_espionagem/types';

async function testD12Logic() {
    console.log('=== ⚖️  D12 ROTTWEILER: LOGIC VERIFICATION ===\n');

    const rottweiler = new DalionRottweiler();

    const scenarios = [
        {
            name: 'CASE 1: Global Consensus (Malicious)',
            d2: { anomaly: true, anomaly_score: 80, risk_level: 'high', tags: ['malicious_activity'], reason: 'Test' } as DetectionResult,
            d3: { ioc_type: 'IP', ioc_value: '1.2.3.4', threat_score: 100, reputation: 'malicious', confidence: 0.9, last_enriched: '', enrichment: {} } as EnrichedIOC,
            expected: 'BLOCK'
        },
        {
            name: 'CASE 2: Zero-Day / Phishing (Local Risk + Global Unknown)',
            d2: { anomaly: true, anomaly_score: 85, risk_level: 'high', tags: ['suspicious_regex'], reason: 'Test' } as DetectionResult,
            d3: { ioc_type: 'domain', ioc_value: 'phish.com', threat_score: 0, reputation: 'unknown', confidence: 0.6, last_enriched: '', enrichment: {} } as EnrichedIOC,
            expected: 'QUARANTINE'
        },
        {
            name: 'CASE 3: Global Intel Override (Local silent, Global says No)',
            d2: { anomaly: false, anomaly_score: 10, risk_level: 'low', tags: [], reason: 'Test' } as DetectionResult,
            d3: { ioc_type: 'IP', ioc_value: '5.6.7.8', threat_score: 95, reputation: 'malicious', confidence: 0.9, last_enriched: '', enrichment: {} } as EnrichedIOC,
            expected: 'BLOCK'
        },
        {
            name: 'CASE 4: Local Emergency Override (Critical Severity)',
            d2: { anomaly: true, anomaly_score: 40, risk_level: 'critical', tags: ['bruteforce_attempt'], reason: 'Test' } as DetectionResult,
            d3: { ioc_type: 'IP', ioc_value: '9.0.1.2', threat_score: 10, reputation: 'clean', confidence: 0.9, last_enriched: '', enrichment: {} } as EnrichedIOC,
            expected: 'BLOCK'
        },
        {
            name: 'CASE 5: Clean Consensus',
            d2: { anomaly: false, anomaly_score: 5, risk_level: 'low', tags: [], reason: 'Test' } as DetectionResult,
            d3: { ioc_type: 'domain', ioc_value: 'google.com', threat_score: 1, reputation: 'clean', confidence: 0.9, last_enriched: '', enrichment: {} } as EnrichedIOC,
            expected: 'ALLOW'
        }
    ];

    let passed = 0;

    scenarios.forEach(s => {
        const decision = rottweiler.decide(s.d2, s.d3);
        const result = decision.action === s.expected ? '✅ PASS' : '❌ FAIL';

        console.log(`${s.name}`);
        console.log(`  D2 Risk: ${s.d2.anomaly_score} (${s.d2.risk_level}) | D3 Rep: ${s.d3.reputation} | Conf: ${s.d3.confidence}`);
        console.log(`  Decision: ${decision.action} | Expected: ${s.expected}`);
        console.log(`  Reason: ${decision.reason}`);
        console.log(`  Status: ${result}\n`);

        if (decision.action === s.expected) passed++;
    });

    console.log('='.repeat(40));
    console.log(`📊 FINAL RESULT: ${passed}/${scenarios.length} PASSED`);
    console.log('='.repeat(40));

    process.exit(passed === scenarios.length ? 0 : 1);
}

testD12Logic().catch(err => {
    console.error('💥 Test crashed:', err);
    process.exit(1);
});
