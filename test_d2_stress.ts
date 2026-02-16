// test_d2_stress.ts
import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { SecurityEvent } from './src/agents/d2_sentinela/types';

async function stressTest() {
    console.log('=== 🔥 STRESS TEST: Heavy Rule Injection ===\n');

    // Adiciona regra PESADA no D2
    const sentinela = new DalionSentinela();

    // Injeta regra custosa
    sentinela.rules.set('stress_test_heavy', {
        name: 'stress_test_heavy',
        description: 'Heavy processing rule',
        impact_score: 50,
        check: async (event, history) => {
            // Simula processamento pesado
            let sum = 0;
            for (let i = 0; i < 10000; i++) {
                sum += Math.sqrt(i);
            }

            // Regex pesado
            const heavyRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
            heavyRegex.test(event.message.repeat(100));

            return false; // Sempre false (só queremos o overhead)
        }
    });

    console.log('🧪 Test 1: Baseline (8 regras leves)');
    const baselineSentinela = new DalionSentinela();

    const mockEvent = (id: string): SecurityEvent => ({
        timestamp: new Date().toISOString(),
        event_id: id,
        log_source_id: 'stress',
        source_ip: '10.0.0.1',
        action: 'login',
        status: 'success',
        severity: 'low' as any,
        message: 'test'
    });

    // Warm up JIT
    for (let i = 0; i < 500; i++) {
        await baselineSentinela.analyze(mockEvent('warmup'));
    }

    const baselineStart = performance.now();

    for (let i = 0; i < 1000; i++) {
        await baselineSentinela.analyze(mockEvent('test'));
    }

    const baselineEnd = performance.now();
    const baselineTime = (baselineEnd - baselineStart) / 1000;
    console.log(`Baseline avg: ${baselineTime.toFixed(4)}ms per event`);

    console.log('\n🔥 Test 2: With Heavy Rule (9 regras, 1 pesada)');
    // Warm up JIT for stress sentinela
    for (let i = 0; i < 500; i++) {
        await sentinela.analyze(mockEvent('warmup'));
    }

    const stressStart = performance.now();

    for (let i = 0; i < 1000; i++) {
        await sentinela.analyze(mockEvent('test'));
    }

    const stressEnd = performance.now();
    const stressTime = (stressEnd - stressStart) / 1000;
    console.log(`Stress avg: ${stressTime.toFixed(4)}ms per event`);

    const degradation = ((stressTime - baselineTime) / baselineTime * 100);
    console.log(`\n📊 Performance degradation: ${degradation.toFixed(1)}%`);

    if (degradation > 500) {
        console.log('✅ CONFIRMED: Heavy rule caused 5x+ slowdown');
        console.log('   → Code is REALLY running!');
    } else if (degradation > 100) {
        console.log('✅ CONFIRMED: Heavy rule caused 2x+ slowdown');
        console.log('   → Code is running, JIT may be optimizing');
    } else {
        console.log('⚠️  SUSPICIOUS: Heavy rule barely affected performance');
        console.log('   → May indicate measurement issue');
    }
}

stressTest();
