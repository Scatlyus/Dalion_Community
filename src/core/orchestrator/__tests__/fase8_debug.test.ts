import { DalionOrchestrator } from '../DalionOrchestrator';
import { DalionSentinela } from '../../../agents/d2_sentinela/index';
import { DalionRottweiler } from '../../../agents/d12_rottweiler/index';
import { SovereignTriad } from '../../triad/SovereignTriad';
import { DalionEventBus } from '../../bus/DalionEventBus';
import { ThreatType } from '../../../agents/d10_ethos/types';

// Mock minimalista para depuração
const makeD3Mock = () => ({
    enrich: jest.fn().mockImplementation(async (request) => {
        console.log(`[DEBUG D3] Enriquecendo IoC:`, request.iocs[0].ioc_value);
        const val = request.iocs[0].ioc_value.toLowerCase();
        const isMalicious = val.includes('xk4jz9mq2rp') || val.includes('malicious-dga-target');
        return {
            enriched_iocs: [{
                ...request.iocs[0],
                threat_score: isMalicious ? 98 : 10,
                reputation: isMalicious ? 'malicious' : 'clean',
                tags: []
            }]
        };
    })
});

const makeD10Mock = () => ({
    classify: jest.fn().mockImplementation(async (enriched) => {
        console.log(`[DEBUG D10] Classificando IoC:`, enriched.ioc_value, 'Score:', enriched.threat_score);
        if (enriched.threat_score >= 80) {
            return {
                threat_type: ThreatType.C2,
                recommended_action: 'block',
                severity: 'critical'
            };
        }
        return { threat_type: ThreatType.CLEAN, recommended_action: 'allow' };
    })
});

describe('Debugger de Cenários Dalion', () => {
    let orchestrator: DalionOrchestrator;

    beforeAll(() => {
        const bus = new DalionEventBus();
        orchestrator = new DalionOrchestrator(
            new DalionSentinela(),
            makeD3Mock() as any,
            makeD10Mock() as any,
            new DalionRottweiler(),
            new SovereignTriad(bus),
            bus
        );
    });

    it('DEBUG S11: DGA Domain Detection', async () => {
        const event: any = {
            timestamp: new Date().toISOString(),
            event_id: 'debug-s11',
            log_source_id: 'debug',
            source_ip: '192.168.1.45',
            action: 'dns',
            status: 'allowed',
            severity: 'medium',
            message: 'DNS query observed',
            metadata: {
                dns: {
                    query: [{ rrname: 'xk4jz9mq2rp.com' }]
                }
            }
        };

        const res = await orchestrator.process(event);
        console.log(`[RESULT S11] Ação Final:`, res.decision.action);
        expect(res.decision.action).toBe('BLOCK');
    });

    it('DEBUG S13: Port Scan rigor', async () => {
        const event: any = {
            timestamp: new Date().toISOString(),
            event_id: 'debug-s13',
            log_source_id: 'debug',
            source_ip: '203.0.113.99',
            action: 'suricata_alert',
            status: 'allowed',
            severity: 'high',
            message: 'ET SCAN Nmap',
            metadata: {
                alert: { signature: 'ET SCAN Nmap', severity: 2 }
            }
        };

        const res = await orchestrator.process(event);
        console.log(`[RESULT S13] Ação Final:`, res.decision.action);
        // Aqui queremos MONITOR, mas vamos ver o que o Rottweiler cospe
    });
});
