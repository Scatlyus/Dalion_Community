import { DalionSentinela } from '../agents/d2_sentinela';
import { SecurityEvent } from '../agents/d2_sentinela/types';

async function testD2() {
    const sentinela = new DalionSentinela();

    console.log("=== 🧪 TESTANDO D2 SENTINELA (Real-World Rules) ===");

    const testCases: SecurityEvent[] = [
        {
            event_id: 'evt-001',
            log_source_id: 'EmailLog',
            timestamp: new Date().toISOString(),
            source_ip: "192.168.1.10",
            email_sender: "admin@microsoft-security-verify.net",
            action: 'url_click',
            status: 'success',
            severity: 'medium',
            message: 'User clicked a link in a PDF'
        },
        {
            event_id: 'evt-002',
            log_source_id: 'NetworkLog',
            timestamp: new Date().toISOString(),
            source_ip: "10.0.0.5",
            destination_ip: "185.123.45.67",
            action: 'outbound_conn',
            status: 'success',
            severity: 'high',
            message: 'Outbound connection to suspicious IP'
        },
        {
            event_id: 'evt-003',
            log_source_id: 'SafeLog',
            timestamp: new Date().toISOString(),
            source_ip: "10.0.0.1",
            action: 'login',
            status: 'success',
            severity: 'informational',
            message: 'Normal user login'
        }
    ];

    for (const [index, log] of testCases.entries()) {
        console.log(`\nCenário ${index + 1}: ${log.log_source_id}`);
        const result = await sentinela.analyze(log);

        if (result.anomaly) {
            console.log(`✅ DETECTADO (Score: ${result.anomaly_score})`);
            console.log(` > Motivos: ${result.reason}`);
            console.log(` > Tags: ${result.tags.join(', ')}`);
        } else {
            console.log(`⚪ Nenhuma anomalia detectada.`);
        }
    }
}

testD2().catch(console.error);
