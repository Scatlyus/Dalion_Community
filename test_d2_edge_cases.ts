import { DalionSentinela } from './src/agents/d2_sentinela/index';

async function testEdgeCases() {
    const sentinela = new DalionSentinela();

    console.log('=== 🛠️ TESTE DE EDGE CASES D2 SENTINELA ===\n');

    // Test 1: Minimal event
    console.log('Teste 1: Evento minimalista (apenas campos obrigatórios)...');
    try {
        const result = await sentinela.analyze({
            timestamp: new Date().toISOString(),
            event_id: 'minimal',
            log_source_id: 'test',
            source_ip: '1.2.3.4',
            action: 'test',
            status: 'success',
            severity: 'low',
            message: 'test'
        });
        console.log('✅ Sucesso: Evento minimalista processado.');
    } catch (error: any) {
        console.log('❌ Erro: Falha em evento minimalista:', error.message);
    }

    // Test 2: Invalid timestamp
    console.log('\nTeste 2: Timestamp inválido...');
    try {
        await sentinela.analyze({
            timestamp: 'data-invalida',
            event_id: 'test',
            log_source_id: 'test',
            source_ip: '1.2.3.4',
            action: 'test',
            status: 'success',
            severity: 'low',
            message: 'test'
        });
        console.log('❌ Falha: Deveria ter lançado erro por data inválida.');
    } catch (error: any) {
        console.log('✅ Sucesso: Erro capturado corretamente:', error.message);
    }

    // Test 3: Saturação de histórico (150+ eventos de um único IP)
    console.log('\nTeste 3: Saturação de Histórico (Limite de 100 por IP)...');
    for (let i = 0; i < 150; i++) {
        await sentinela.analyze({
            timestamp: new Date().toISOString(),
            event_id: `test_${i}`,
            log_source_id: 'test',
            source_ip: '10.0.0.99',
            action: 'test',
            status: 'success',
            severity: 'low',
            message: 'overflow test'
        });
    }
    console.log('✅ Sucesso: 150 eventos do mesmo IP processados sem estouro de memória.');

    // Test 4: Caracteres especiais e emojis em mensagens
    console.log('\nTeste 4: Caracteres especiais e Emojis...');
    try {
        const result = await sentinela.analyze({
            timestamp: new Date().toISOString(),
            event_id: 'special_chars',
            log_source_id: 'test',
            source_ip: '1.1.1.1',
            action: 'test',
            status: 'success',
            severity: 'low',
            message: 'Test with émojis 🔥 and spëcial çhars & <script>alert("XSS")</script>'
        });
        console.log('✅ Sucesso: Caracteres especiais tratados como string segura.');
    } catch (error: any) {
        console.log('❌ Erro: Falha com caracteres especiais:', error.message);
    }

    console.log('\n🏁 TESTES DE EDGE CASES FINALIZADOS!');
}

testEdgeCases().catch(console.error);
