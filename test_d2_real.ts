import { DalionSentinela } from './src/agents/d2_sentinela/index';
import { SecurityEvent } from './src/agents/d2_sentinela/types';

async function main() {
    const sentinela = new DalionSentinela();

    const testCases: SecurityEvent[] = [
        {
            timestamp: new Date().toISOString(),
            event_id: 'login_failure',
            log_source_id: 'win_sec',
            source_ip: '10.0.0.1',
            action: 'login',
            status: 'failure',
            severity: 'medium',
            message: 'Failed login attempt'
        },
        {
            timestamp: new Date().toISOString(),
            event_id: 'malicious_connection',
            log_source_id: 'firewall',
            source_ip: '192.168.1.100',
            destination_ip: '185.123.45.67', // IoC List
            action: 'connect',
            status: 'allowed',
            severity: 'high',
            message: 'Connection to known C2 IP'
        },
        {
            timestamp: new Date().toISOString(),
            event_id: 'email_phishing',
            log_source_id: 'o365',
            source_ip: '203.0.113.5',
            action: 'receive',
            status: 'success',
            severity: 'critical',
            message: 'Email containing suspicious link and phishing landing page',
            email_sender: 'security@microsoft-security-verify.com' // IoC Domain
        },
        {
            timestamp: '2026-02-13T03:00:00Z', // Night hour
            event_id: 'odd_hour_login',
            log_source_id: 'vpn',
            source_ip: '45.1.2.3',
            action: 'login',
            status: 'success',
            severity: 'low',
            message: 'User logged in at 3 AM'
        },
        {
            timestamp: new Date().toISOString(),
            event_id: 'file_creation',
            log_source_id: 'edr',
            source_ip: '10.0.0.50',
            action: 'write',
            status: 'success',
            severity: 'high',
            message: 'Executable created in temp directory',
            file_path: 'C:\\Windows\\Temp\\payload.exe'
        }
    ];

    console.log("=== 🧪 Validando D2 Sentinela Real (Full Heuristics) ===");

    // Test Burst logic (sending 3 failures)
    const burstIP = '1.1.1.1';
    console.log(`\n--- Testando Burst Logic para IP ${burstIP} ---`);
    for (let i = 1; i <= 3; i++) {
        const burstEvent: SecurityEvent = {
            timestamp: new Date().toISOString(),
            event_id: 'login_failure',
            log_source_id: 'test',
            source_ip: burstIP,
            action: 'login',
            status: 'failure',
            severity: 'medium',
            message: `Attempt ${i}`
        };
        const r = await sentinela.analyze(burstEvent);
        console.log(`Tentativa ${i}: ${r.anomaly ? '🚨 ANOMALIA' : '⚪ OK'} (Score: ${r.anomaly_score})`);
    }

    console.log(`\n--- Testando Regras Diversas ---`);
    for (const event of testCases) {
        const result = await sentinela.analyze(event);
        console.log(`\nEvento: ${event.event_id} | Msg: ${event.message.substring(0, 30)}...`);
        console.log(`Result: ${result.anomaly ? '🚨 ANOMALIA' : '⚪ OK'} | Score: ${result.anomaly_score}`);
        if (result.anomaly) {
            console.log(`Reasons: ${result.reason}`);
            console.log(`Tags: ${result.tags.join(', ')}`);
        }
    }
}

main().catch(console.error);
