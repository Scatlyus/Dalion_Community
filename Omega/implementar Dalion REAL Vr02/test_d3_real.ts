#!/usr/bin/env node

/**
 * D3 Espionagem - Real World Test
 * 
 * Tests enrichment with REAL VirusTotal and AbuseIPDB APIs
 * Requires valid API keys in .env
 */

import * as dotenv from 'dotenv';
import { DalionEspionagem } from './src/agents/d3_espionagem';
import { D3Config, IOC } from './src/agents/d3_espionagem/types';

// Load environment variables
dotenv.config();

async function testD3Real() {
  console.log('=== 🕵️ D3 ESPIONAGEM: REAL API TEST ===\n');

  // Validate API keys
  const vtKey = process.env.VT_API_KEY;
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

  if (!vtKey || vtKey === 'your_virustotal_key_here') {
    console.error('❌ Missing VirusTotal API key in .env');
    console.log('Get one at: https://www.virustotal.com/gui/join-us\n');
    process.exit(1);
  }

  if (!abuseKey || abuseKey === 'your_abuseipdb_key_here') {
    console.error('❌ Missing AbuseIPDB API key in .env');
    console.log('Get one at: https://www.abuseipdb.com/register\n');
    process.exit(1);
  }

  console.log('✅ API keys validated\n');

  // Configure D3
  const config: D3Config = {
    virustotal: {
      api_key: vtKey,
      rate_limit: {
        max_requests: 4,
        per_minutes: 1
      },
      timeout_ms: 10000
    },
    abuseipdb: {
      api_key: abuseKey,
      rate_limit: {
        max_requests: 1000,
        per_day: 1
      },
      timeout_ms: 10000
    },
    cache: {
      enabled: true,
      redis_url: redisUrl,
      ttl_seconds: 3600
    },
    conflict_resolution: {
      strategy: 'most_severe'
    }
  };

  // Initialize D3
  console.log('🔧 Initializing D3 Espionagem...');
  const espionagem = new DalionEspionagem(config);
  console.log('✅ D3 ready\n');

  // Test IOCs (known malicious)
  const testIOCs: IOC[] = [
    {
      ioc_type: 'domain',
      ioc_value: 'microsoft-security-verify.com', // Known phishing
      is_anomaly: true,
      context: { source: 'KC7_dataset' }
    },
    {
      ioc_type: 'IP',
      ioc_value: '185.123.45.67', // Example malicious IP
      is_anomaly: true,
      context: { source: 'D2_sentinela' }
    },
    {
      ioc_type: 'domain',
      ioc_value: 'google.com', // Known clean (control)
      is_anomaly: false,
      context: { source: 'baseline_test' }
    }
  ];

  console.log('📊 Test IOCs:');
  testIOCs.forEach((ioc, i) => {
    console.log(`  ${i + 1}. ${ioc.ioc_type}: ${ioc.ioc_value}`);
  });
  console.log('');

  // Enrich
  console.log('🔍 Enriching IOCs (this may take 15-30 seconds due to rate limits)...\n');
  
  const startTime = performance.now();

  try {
    const result = await espionagem.enrich({
      iocs: testIOCs,
      sources_priority: ['VirusTotal', 'AbuseIPDB'],
      analysis_depth: 'medium',
      use_cache: true
    });

    const endTime = performance.now();
    const totalTime = endTime - startTime;

    console.log('✅ Enrichment complete!\n');
    console.log('='.repeat(60));
    console.log('📊 ENRICHMENT RESULTS');
    console.log('='.repeat(60));

    // Display results
    result.enriched_iocs.forEach((enriched, i) => {
      console.log(`\n${i + 1}. ${enriched.ioc_type.toUpperCase()}: ${enriched.ioc_value}`);
      console.log(`   Reputation: ${enriched.reputation.toUpperCase()}`);
      console.log(`   Threat Score: ${enriched.threat_score}/100`);
      console.log(`   Confidence: ${(enriched.confidence * 100).toFixed(0)}%`);

      if (enriched.enrichment.virustotal) {
        const vt = enriched.enrichment.virustotal;
        console.log(`   VirusTotal:`);
        console.log(`     - Malicious: ${vt.last_analysis_stats.malicious}`);
        console.log(`     - Suspicious: ${vt.last_analysis_stats.suspicious}`);
        console.log(`     - Clean: ${vt.last_analysis_stats.harmless}`);
        console.log(`     - Reputation: ${vt.reputation_score.toFixed(2)}`);
      }

      if (enriched.enrichment.abuseipdb) {
        const abuse = enriched.enrichment.abuseipdb;
        console.log(`   AbuseIPDB:`);
        console.log(`     - Confidence Score: ${abuse.abuse_confidence_score}/100`);
        console.log(`     - Total Reports: ${abuse.total_reports}`);
        console.log(`     - Country: ${abuse.country_code || 'Unknown'}`);
        console.log(`     - Whitelisted: ${abuse.is_whitelisted ? 'Yes' : 'No'}`);
      }
    });

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('📈 SUMMARY REPORT');
    console.log('='.repeat(60));
    console.log(`Total IOCs: ${result.summary_report.total_iocs}`);
    console.log(`Malicious: ${result.summary_report.malicious_count}`);
    console.log(`Suspicious: ${result.summary_report.suspicious_count}`);
    console.log(`Clean: ${result.summary_report.clean_count}`);
    console.log(`Unknown: ${result.summary_report.unknown_count}`);
    console.log(`Sources used: ${result.summary_report.sources_used.join(', ')}`);
    console.log(`Cache hits: ${result.summary_report.cache_hits}`);
    console.log(`API calls: ${result.summary_report.api_calls_made}`);
    console.log(`Total time: ${(totalTime / 1000).toFixed(2)}s`);
    console.log(`Avg per IOC: ${(totalTime / result.summary_report.total_iocs).toFixed(0)}ms`);

    // Performance analysis
    console.log('\n' + '='.repeat(60));
    console.log('⚡ PERFORMANCE ANALYSIS');
    console.log('='.repeat(60));
    
    const avgTime = totalTime / result.summary_report.total_iocs;
    if (avgTime < 5000) {
      console.log('✅ EXCELLENT: < 5s per IOC (cache hit or fast API)');
    } else if (avgTime < 15000) {
      console.log('✅ GOOD: 5-15s per IOC (rate limiting expected)');
    } else {
      console.log('⚠️  SLOW: > 15s per IOC (check network/API status)');
    }

    // Validation
    console.log('\n' + '='.repeat(60));
    console.log('🎯 VALIDATION');
    console.log('='.repeat(60));

    const hasRealData = result.enriched_iocs.some(ioc => 
      ioc.enrichment.virustotal || ioc.enrichment.abuseipdb
    );

    if (!hasRealData) {
      console.log('❌ FAILED: No enrichment data received');
      console.log('   Check API keys and network connectivity');
    } else {
      console.log('✅ PASSED: Real enrichment data received');
      
      const maliciousDetected = result.summary_report.malicious_count > 0;
      const cleanDetected = result.summary_report.clean_count > 0;

      if (maliciousDetected && cleanDetected) {
        console.log('✅ PASSED: Both malicious and clean IOCs correctly classified');
      } else {
        console.log('⚠️  WARNING: Classification may need review');
      }
    }

  } catch (error) {
    console.error('\n❌ Enrichment failed:', error.message);
    console.error('\nDetails:', error);
    process.exit(1);
  } finally {
    await espionagem.close();
  }

  console.log('\n🎉 D3 ESPIONAGEM: TEST COMPLETE!\n');
}

// Run test
testD3Real().catch(error => {
  console.error('💥 Test crashed:', error);
  process.exit(1);
});
