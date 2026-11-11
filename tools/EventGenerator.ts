import { SecurityEvent } from '../src/agents/d2_sentinela/types';

export class EventGenerator {
    /**
     * Gera uma massa de eventos aleatórios (ruído).
     */
    generateNoise(count: number, baseIp: string = '192.168.1.'): SecurityEvent[] {
        const events: SecurityEvent[] = [];
        for (let i = 0; i < count; i++) {
            events.push({
                timestamp: new Date().toISOString(),
                event_id: `NOISE-${i}`,
                log_source_id: 'GENERIC-GATEWAY',
                source_ip: `${baseIp}${Math.floor(Math.random() * 254)}`,
                action: 'web_request',
                status: 'success',
                severity: 'informational',
                message: `GET /assets/static_${Math.floor(Math.random() * 100)}.js`
            });
        }
        return events;
    }

    /**
     * Gera uma sequência de ataque APT (MITRE Kill Chain).
     */
    generateAPTSequence(attackerIp: string): Array<{ event: SecurityEvent, phase: any }> {
        // Import inline to avoid circular deps if any
        const { MITREPhase } = require('../src/agents/d9_attackgraph/types');

        return [
            {
                phase: MITREPhase.INITIAL_ACCESS,
                event: {
                    timestamp: new Date().toISOString(),
                    event_id: 'APT-001',
                    log_source_id: 'EMAIL-SEC',
                    source_ip: attackerIp,
                    action: 'phishing_click',
                    status: 'success',
                    severity: 'high',
                    message: 'User clicked on malicious attachment'
                }
            },
            {
                phase: MITREPhase.EXECUTION,
                event: {
                    timestamp: new Date().toISOString(),
                    event_id: 'APT-002',
                    log_source_id: 'ENDPOINT',
                    source_ip: attackerIp,
                    action: 'powershell_exec',
                    status: 'success',
                    severity: 'critical',
                    message: 'Encoded powershell command executed'
                }
            },
            {
                phase: MITREPhase.PERSISTENCE,
                event: {
                    timestamp: new Date().toISOString(),
                    event_id: 'APT-003',
                    log_source_id: 'SYSTEM',
                    source_ip: attackerIp,
                    action: 'reg_modify',
                    status: 'success',
                    severity: 'medium',
                    message: 'Registry RUN key modified for persistent bin'
                }
            }
        ];
    }
}
