import { DalionSentinela } from './src/agents/d2_sentinela/index';

async function testSpecificIP() {
    const sentinela = new DalionSentinela();
    const testEvent = {
        timestamp: new Date().toISOString(),
        event_id: 'network_connection',
        log_source_id: 'firewall',
        source_ip: '45.133.1.25',  // C2 IP que antes missed
        destination_ip: '10.0.0.100',
        destination_port: 4444,
        action: 'connection',
        status: 'success',
        severity: 'medium',
        message: 'Outbound connection'
    };

    console.log('--- 🛡️  SPECIFIC IP TEST: 45.133.1.25 ---');
    const result = await sentinela.analyze(testEvent as any);
    console.log('Result:', JSON.stringify(result, null, 2));
}

testSpecificIP().catch(console.error);
