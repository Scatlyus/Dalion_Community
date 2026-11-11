// @ts-nocheck
import { DalionEspionagem } from './src/agents/d3_espionagem/index';
import RedisMock from 'ioredis-mock';
import { D3Config } from './src/agents/d3_espionagem/types';

async function testRedisCache() {
    console.log('=== 🧪 D3 REDIS CACHE INTEGRATION TEST ===');

    // 1. Setup Mock Redis
    const redisMock = new RedisMock();

    // 2. Setup D3 with Mock Config and Injected Redis
    const config: D3Config = {
        virustotal: { api_key: 'mock_vt', rate_limit: { max_requests: 10, per_minutes: 1 }, timeout_ms: 1000 },
        abuseipdb: { api_key: 'mock_abuse', rate_limit: { max_requests: 10, per_day: 1 }, timeout_ms: 1000 },
        cache: { enabled: true, redis_url: 'redis://localhost:6379', ttl_seconds: 60 },
        conflict_resolution: { strategy: 'most_severe' }
    };

    const d3 = new DalionEspionagem(config, redisMock);

    // Mock internal clients to avoid real API calls
    d3.vtClient.getIPReport = async (ip) => ({ reputation_score: -0.5, last_analysis_stats: { malicious: 5 } });
    d3.abuseIPDBClient.checkIP = async (ip) => ({ abuse_confidence_score: 80 });

    const targetIOC = { ioc_type: 'IP', ioc_value: '1.2.3.4', is_anomaly: true };

    // 3. Test 1: Cache MISS (First Call)
    console.log('\n[Step 1] First Call (Should be MISS)...');
    const result1 = await d3.enrich({ iocs: [targetIOC] });
    const stats1 = d3.getStats();

    console.log(`Cache Hits: ${stats1.cache_hits}`);
    console.log(`Cache Misses: ${stats1.cache_misses}`);

    if (stats1.cache_misses !== 1 || stats1.cache_hits !== 0) {
        console.error('❌ FAILED: Expected 1 miss, 0 hits');
        process.exit(1);
    }

    // Verify Redis has data
    const cachedData = await redisMock.get('d3:IP:1.2.3.4');
    if (cachedData) {
        console.log('✅ Redis has data:', JSON.parse(cachedData).ioc_value);
    } else {
        console.error('❌ FAILED: Redis key not set');
        process.exit(1);
    }

    // 4. Test 2: Cache HIT (Second Call)
    console.log('\n[Step 2] Second Call (Should be HIT)...');
    const result2 = await d3.enrich({ iocs: [targetIOC] });
    const stats2 = d3.getStats();

    console.log(`Cache Hits: ${stats2.cache_hits}`);
    console.log(`Cache Misses: ${stats2.cache_misses}`);

    if (stats2.cache_hits !== 1) {
        console.error('❌ FAILED: Expected 1 hit');
        process.exit(1);
    }

    console.log('\n✅ SUCCESS: Redis Caching is working correctly!');
    await d3.close();
}

testRedisCache().catch(error => { console.error(error); process.exitCode = 1; });
