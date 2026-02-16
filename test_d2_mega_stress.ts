// test_d2_mega_stress.ts
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { SecurityEvent } from './src/agents/d2_sentinela/types';

async function megaStressTest() {
    console.log('=== 🚀 MEGA STRESS TEST: Absolute Certification ===\n');

    const sentinela = new DalionSentinela();

    // Injeta regra MEGA custosa
    sentinela.rules.set('mega_stress', {
        name: 'mega_stress',
        description: 'MEGA heavy rule',
        impact_score: 50,
        check: async (event, history) => {
            // 100,000 iterações com Math complexo
            let sum = 0;
            for (let i = 0; i < 100000; i++) {
                sum += Math.sqrt(i) * Math.sin(i) * Math.cos(i);
            }

            // Regex pesado em string LONGA
            const longString = 'a'.repeat(10000) + 'A1@';
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(longString);

            // Processa histórico (TTL Simulation/Filter overhead)
            const h = history.get(event.source_ip) || [];
            h.filter(e => e.timestamp.includes('2026')).length;

            return false;
        }
    });

    const mockEvent = (id: string): SecurityEvent => ({
        timestamp: new Date().toISOString(),
        event_id: id,
        log_source_id: 'stress',
        source_ip: '10.0.0.1',
        action: 'login',
        status: 'success',
        severity: 'low' as any,
        message: 'test message with some keywords exploit malware'
    });

    console.log('🧪 Step 1: Baseline (8 regras leves)');
    const baselineSentinela = new DalionSentinela();

    // JIT Warmup
    for (let i = 0; i < 500; i++) await baselineSentinela.analyze(mockEvent('warmup'));

    const baselineStart = performance.now();
    for (let i = 0; i < 1000; i++) await baselineSentinela.analyze(mockEvent('test'));
    const baselineEnd = performance.now();

    const baselineTime = (baselineEnd - baselineStart) / 1000;
    console.log(`Baseline avg: ${baselineTime.toFixed(4)}ms per event`);

    console.log('\n🔥 Step 2: Mega Stress (9 regras, 1 MEGA pesada)');
    // JIT Warmup for mega
    for (let i = 0; i < 100; i++) await sentinela.analyze(mockEvent('warmup'));

    const stressStart = performance.now();
    // Reduzi para 100 iterações porque o mega_stress vai ser LENTO
    const iterations = 100;
    for (let i = 0; i < iterations; i++) {
        await sentinela.analyze(mockEvent('test'));
    }
    const stressEnd = performance.now();

    const stressTime = (stressEnd - stressStart) / iterations;
    console.log(`Mega Stress avg: ${stressTime.toFixed(4)}ms per event`);

    const degradation = ((stressTime - baselineTime) / baselineTime * 100);
    console.log(`\n📊 Performance degradation: ${degradation.toFixed(1)}%`);

    if (degradation > 1000) {
        console.log('✅ ABSOLUTELY CERTIFIED: 10x+ slowdown confirmed');
        console.log('   → No doubt: Code is running at scale!');
    } else {
        console.log('⚠️  INTERESTING: Even 100k iterations are fast? V8 is a monster.');
    }
}

megaStressTest();
