import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { performance } from 'perf_hooks';

async function testPerformance() {
    const sentinela = new DalionSentinela();

    console.log('=== 🚀 TESTE DE PERFORMANCE D2 SENTINELA (WAR MODE) ===\n');

    const ITERATIONS = 10000;
    const sameIP = '1.1.1.1';

    console.log(`Teste 1: Processando ${ITERATIONS} eventos (Carga Real)...`);
    const result = await sentinela.analyze({
        timestamp: new Date().toISOString(),
        event_id: `perf_probe`,
        log_source_id: 'perf_test',
        source_ip: sameIP,
        action: 'login',
        status: 'failure',
        severity: 'medium',
        message: 'audit test'
    });
    console.log(`🔍 Auditoria: Cada evento está processando ${result.rules_processed} regras.`);

    const start = performance.now();

    for (let i = 0; i < ITERATIONS; i++) {
        await sentinela.analyze({
            timestamp: new Date().toISOString(),
            event_id: `perf_${i}`,
            log_source_id: 'perf_test',
            source_ip: sameIP, // Usando o mesmo IP para forçar análise de histórico O(N)
            action: 'login',
            status: 'failure',
            severity: 'medium',
            message: 'test performance event with some sensitive terms like ransomware and exploit'
        });
    }

    const end = performance.now();
    const totalTime = end - start;
    const avg = totalTime / ITERATIONS;

    console.log(`⏱️ Tempo total: ${totalTime.toFixed(2)}ms`);
    console.log(`⏱️ Tempo médio por evento: ${avg.toFixed(3)}ms`);
    console.log(`⚡ Throughput: ${(1000 / avg).toFixed(0)} eventos/segundo`);

    // Test 2: Stress de memória
    console.log('\nTeste 2: Verificação de Saturação de Memória...');
    const before = process.memoryUsage().heapUsed;

    // Processar 5 IP000 eventos de IPs diferentes para encher o Map
    for (let i = 0; i < 5000; i++) {
        await sentinela.analyze({
            timestamp: new Date().toISOString(),
            event_id: `mem_${i}`,
            log_source_id: 'mem_test',
            source_ip: `192.168.100.${i % 255}.${Math.floor(i / 255)}`,
            action: 'test',
            status: 'success',
            severity: 'low',
            message: 'memory stress test event'
        });
    }

    const after = process.memoryUsage().heapUsed;
    const usedMB = (after - before) / 1024 / 1024;

    console.log(`📈 Memória Heap utilizada: ${usedMB.toFixed(2)} MB`);

    if (avg < 5.0) {
        console.log('\n✅ PERFORMANCE EXCELENTE PARA PRODUÇÃO.');
    } else if (avg < 20.0) {
        console.log('\n✅ PERFORMANCE DENTRO DO ACEITÁVEL.');
    } else {
        console.log('\n⚠️ PERFORMANE ABAIXO DO ESPERADO.');
    }
}

testPerformance().catch(console.error);
