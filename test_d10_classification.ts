import { DalionEthos } from './src/agents/d10_ethos/index';
import { ThreatType } from './src/agents/d10_ethos/types';

async function runD10Tests() {
    console.log('=== 🧠 DALION D10 ETHOS: TAXONOMY VERIFICATION ===\n');

    const ethos = new DalionEthos();

    const scenarios = [
        {
            name: 'Scenario 1: Ransomware Domain',
            mock: {
                ioc_value: 'cryptolocker-pay.com',
                ioc_type: 'domain',
                threat_score: 100,
                confidence: 0.9,
                enrichment: {
                    virustotal: { categories: ['ransomware', 'malicious'] }
                },
                tags: []
            },
            expected: ThreatType.RANSOMWARE
        },
        {
            name: 'Scenario 2: Phishing Campaign',
            mock: {
                ioc_value: 'netflix-secure-login.net',
                ioc_type: 'domain',
                threat_score: 85,
                confidence: 0.8,
                enrichment: {
                    virustotal: { categories: ['phishing'] }
                },
                tags: []
            },
            expected: ThreatType.PHISHING
        },
        {
            name: 'Scenario 3: Active C2 Beacon',
            mock: {
                ioc_value: '45.133.1.25',
                ioc_type: 'IP',
                threat_score: 70,
                confidence: 0.6,
                enrichment: {
                    virustotal: { categories: ['c2'] }
                },
                tags: ['c2_communication_pattern']
            },
            expected: ThreatType.C2
        },
        {
            name: 'Scenario 4: Clean Infrastructure',
            mock: {
                ioc_value: 'google.com',
                ioc_type: 'domain',
                threat_score: 0,
                confidence: 1.0,
                enrichment: {
                    virustotal: { categories: [] }
                },
                tags: []
            },
            expected: ThreatType.CLEAN
        }
    ];

    let passed = 0;

    for (const scenario of scenarios) {
        console.log(`Testing ${scenario.name}...`);
        const result = await ethos.classify(scenario.mock as any);

        const isSuccess = result.threat_type === scenario.expected;
        if (isSuccess) {
            console.log(`✅ SUCCESS: Detected as ${result.threat_type} (Severity: ${result.severity})`);
            console.log(`   MITRE Tactics: ${result.mitre_tactics.join(', ')}`);
            passed++;
        } else {
            console.log(`❌ FAILED: Expected ${scenario.expected}, but got ${result.threat_type}`);
        }
        console.log('-'.repeat(40));
    }

    console.log(`\nFinal Result: ${passed}/${scenarios.length} PASSED`);
}

runD10Tests().catch(console.error);
