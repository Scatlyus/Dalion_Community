import * as dotenv from 'dotenv';
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { DalionEspionagem } from './src/agents/d3_espionagem/index';
import { DalionEthos } from './src/agents/d10_ethos/index';
import { DalionRottweiler } from './src/agents/d12_rottweiler/index';

dotenv.config();

async function runWildFireTests() {
    console.log('=== 🔥 DALION VR01: WILD FIRE STRESS TEST ===');
    console.log('Testing Zero-Days, Trick Cases & Advanced Taxonomies\n');

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

    const wildScenarios = [
        {
            id: 'WILD-001',
            name: 'Zero-Day Phishing (Unknown to Intel)',
            ioc_type: 'domain',
            ioc_value: 'google-security-verify.net',
            scenario: 'Suspicious domain name targeting Google, but brand new (unknown in global feeds)',
            expected_action: 'BLOCK'
        },
        {
            id: 'WILD-002',
            name: 'Malicious CIDR Match (Static Intel)',
            ioc_type: 'IP',
            ioc_value: '185.123.1.50',
            scenario: 'IP from a known malicious range, even if specific IP is not yet blacklisted',
            expected_action: 'BLOCK'
        },
        {
            id: 'WILD-003',
            name: 'Ransomware Taxonomy Response',
            ioc_type: 'domain',
            ioc_value: 'locky-crypto-payment.biz',
            scenario: 'Global intel flags as ransomware category',
            expected_action: 'ISOLATE_HOST'
        },
        {
            id: 'WILD-004',
            name: 'False Positive Resistance (High Load Legit)',
            ioc_type: 'IP',
            ioc_value: '8.8.8.8',
            scenario: 'Regular outbound to DNS servers, should not be blocked despite volume',
            expected_action: 'MONITOR' // Or ALLOW depending on confidence
        }
    ];

    for (const scenario of wildScenarios) {
        console.log(`\n[${scenario.id}] Scenario: ${scenario.name}`);
        console.log(`   Description: ${scenario.scenario}`);
        console.log(`   Target: ${scenario.ioc_value}`);

        // 1. D2 Heuristics
        const event = {
            timestamp: new Date().toISOString(),
            event_id: `evt-${scenario.id}`,
            log_source_id: 'ENDPOINT_FIREWALL',
            source_ip: scenario.ioc_type === 'IP' ? scenario.ioc_value : '10.0.0.50',
            action: 'network_connect',
            status: 'allowed',
            severity: 'medium',
            message: `Outbound to ${scenario.ioc_value}`,
            email_sender: scenario.name.includes('Phishing') ? `admin@${scenario.ioc_value}` : undefined
        };

        const d2Result = await d2.analyze(event as any);

        // 2. D3 Enrichment
        // We mock some enrichment categories for Scenario 3 to force D10 classification
        const d3ResultRaw: any = await d3.enrich({
            iocs: [{ ioc_type: scenario.ioc_type as any, ioc_value: scenario.ioc_value, is_anomaly: d2Result.anomaly }],
            use_cache: false
        });
        const enrichedIOC = d3ResultRaw.enriched_iocs[0];

        // MERGE: Adiciona as tags de heurística do D2 para o D10 poder classificar corretamente
        enrichedIOC.tags = [...(enrichedIOC.tags || []), ...(d2Result.tags || [])];

        // Force ransomware category for W-003 to test D10/D12 integration
        if (scenario.id === 'WILD-003') {
            enrichedIOC.enrichment.virustotal = {
                ...enrichedIOC.enrichment.virustotal,
                categories: ['ransomware', 'malicious']
            };
            enrichedIOC.threat_score = 100;
            enrichedIOC.reputation = 'malicious';
        }

        // 3. D10 Classification
        const d10Result = await d10.classify(enrichedIOC);

        // 4. D12 Decision
        const decision = d12.decide(d2Result, enrichedIOC, d10Result);

        console.log(`   >>> D2 Score: ${d2Result.anomaly_score} (${d2Result.risk_level})`);
        console.log(`   >>> D10 Type: ${d10Result.threat_type} (Tactics: ${d10Result.mitre_tactics.join(', ')})`);
        console.log(`   >>> D12 ACTION: ${decision.action}`);
        console.log(`   >>> REASON: ${decision.reason}`);

        if (decision.action === scenario.expected_action) {
            console.log('   ✅ TEST PASSED');
        } else {
            console.log(`   ❌ TEST FAILED (Expected ${scenario.expected_action})`);
        }
    }

    await d3.close();
    console.log('\n=== WILD FIRE TEST COMPLETE ===');
}

runWildFireTests().catch(console.error);
