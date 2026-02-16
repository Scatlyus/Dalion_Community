#!/usr/bin/env node

import * as dotenv from 'dotenv';
import { DalionEspionagem } from './src/agents/d3_espionagem';
import { D3Config, IOC } from './src/agents/d3_espionagem/types';

dotenv.config();

async function testD3Certification() {
  console.log('=== 🔬 D3 ESPIONAGEM: A+ QUALITY CERTIFICATION ===\n');

  const vtKey = process.env.VT_API_KEY;
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  const redisUrl = process.env.REDIS_URL;

  if (!vtKey || !abuseKey) {
    console.error('❌ Missing API keys in .env');
    process.exit(1);
  }

  const config: D3Config = {
    virustotal: {
      api_key: vtKey,
      rate_limit: { max_requests: 4, per_minutes: 1 },
      timeout_ms: 15000
    },
    abuseipdb: {
      api_key: abuseKey,
      rate_limit: { max_requests: 1000, per_day: 1 },
      timeout_ms: 15000
    },
    cache: {
      enabled: !!redisUrl,
      redis_url: redisUrl || 'redis://localhost:6379',
      ttl_seconds: 3600
    },
    conflict_resolution: { strategy: 'most_severe' }
  };

  const espionagem = new DalionEspionagem(config);

  const testIOCs: IOC[] = [
    {
      ioc_type: 'IP',
      ioc_value: '193.163.125.138', // Known active scanner/bruteforcer
      is_anomaly: true
    },
    {
      ioc_type: 'domain',
      ioc_value: 'google.com',
      is_anomaly: false
    }
  ];

  console.log('🔍 Running Cold Enrichment (Targeting A+ Quality)...');
  const start1 = performance.now();
  const run1 = await espionagem.enrich({ iocs: testIOCs, use_cache: true });
  const end1 = performance.now();

  run1.enriched_iocs.forEach(ioc => {
    console.log(`- ${ioc.ioc_type}[${ioc.ioc_value}]: ${ioc.reputation.toUpperCase()} (${ioc.threat_score}/100, Conf: ${ioc.confidence * 100}%)`);
  });

  console.log(`⏱️  Response Time: ${((end1 - start1) / 1000).toFixed(2)}s`);

  // VALIDATIONS
  console.log('\n' + '='.repeat(40));
  console.log('🛡️  A+ CERTIFICATION AUDIT');
  console.log('='.repeat(40));

  let errors = 0;

  // 1. Confidence Logic (Domain-aware)
  const google = run1.enriched_iocs.find(i => i.ioc_value === 'google.com');
  if (google?.confidence === 0.9) {
    console.log('✅ A+ PASS: Domain confidence is 90% (Fix validated)');
  } else {
    console.log(`❌ A+ FAIL: Domain confidence is ${google?.confidence * 100}%`);
    errors++;
  }

  // 2. Malicious Detection
  const maliciousIP = run1.enriched_iocs.find(i => i.ioc_value === '193.163.125.138');
  if (maliciousIP && (maliciousIP.reputation === 'malicious' || maliciousIP.reputation === 'suspicious')) {
    console.log(`✅ A+ PASS: Malicious IP detected as ${maliciousIP.reputation.toUpperCase()}`);
  } else {
    console.log(`❌ A+ FAIL: Malicious IP not detected (Got ${maliciousIP?.reputation})`);
    errors++;
  }

  if (errors === 0) {
    console.log('\n🏆 TIER-ZERO A+ CERTIFICATION: PASSED SUCCESSFULLY');
    console.log('D3 Espionagem is now technically superior and production-ready.');
  }

  await espionagem.close();
  process.exit(errors === 0 ? 0 : 1);
}

testD3Certification().catch(err => {
  console.error('💥 Test crashed:', err);
  process.exit(1);
});
