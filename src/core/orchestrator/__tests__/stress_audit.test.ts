import { DalionOrchestrator } from '../DalionOrchestrator';
import { DalionSentinela } from '../../../agents/d2_sentinela/index';
import { DalionRottweiler } from '../../../agents/d12_rottweiler/index';
import { SovereignTriad } from '../../triad/SovereignTriad';
import { DalionEventBus } from '../../bus/DalionEventBus';
import { ThreatType } from '../../../agents/d10_ethos/types';
import { SecurityEvent } from '../../../agents/d2_sentinela/types';

// Mock de alta performance para stress
const makeD3Mock = () => ({
    enrich: jest.fn().mockImplementation(async (request) => {
        // Simula latência variável (10ms a 50ms)
        await new Promise(resolve => setTimeout(resolve, Math.random() * 40 + 10));
        return {
            enriched_iocs: request.iocs.map((ioc: any) => ({
                ...ioc,
                threat_score: ioc.ioc_value.includes('malicious') ? 95 : 5,
                confidence: 0.9,
                reputation: ioc.ioc_value.includes('malicious') ? 'malicious' : 'clean',
                tags: []
            })),
            summary_report: {}
        };
    })
});

const makeD10Mock = () => ({
    classify: jest.fn().mockImplementation(async (enriched: any) => {
        if (enriched.threat_score >= 80) {
            return {
                threat_type: ThreatType.MALWARE,
                recommended_action: 'block',
                severity: 'critical'
            };
        }
        return { threat_type: ThreatType.CLEAN, recommended_action: 'allow' };
    })
});

describe('Dalion Stress & Concurrency Audit (System Load)', () => {
    let orchestrator: DalionOrchestrator;
    const TOTAL_EVENTS = 200; // Carga de stress razoável para unit test

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

    it(`deve processar ${TOTAL_EVENTS} eventos simultâneos sem corromper memória`, async () => {
        const start = Date.now();

        const events: SecurityEvent[] = Array.from({ length: TOTAL_EVENTS }, (_, i) => ({
            timestamp: new Date().toISOString(),
            event_id: `stress-${i}`,
            log_source_id: 'stress-test',
            source_ip: `192.168.1.${i % 254}`,
            action: 'http',
            status: 'allowed' as const,
            severity: 'medium' as const,
            message: 'Stress test event',
            metadata: {
                http: {
                    hostname: i % 10 === 0 ? 'malicious-domain.com' : 'legit-site.com',
                    url: '/test'
                }
            }
        }));

        console.log(`[STRESS] Iniciando disparo de ${TOTAL_EVENTS} eventos...`);

        // Disparo massivo paralelo
        const promises = events.map(event => orchestrator.process(event));
        const results = await Promise.all(promises);

        const duration = Date.now() - start;
        const blocks = results.filter(r => r.decision.action === 'BLOCK' || r.decision.action === 'QUARANTINE').length;

        console.log(`[STRESS] Processamento concluído em ${duration}ms`);
        console.log(`[STRESS] Eventos Detectados: ${blocks}`);
        console.log(`[STRESS] RPS (Requests Per Second): ${(TOTAL_EVENTS / (duration / 1000)).toFixed(2)}`);

        expect(results.length).toBe(TOTAL_EVENTS);
        // Esperamos que 1 a cada 10 eventos sejam bloqueados (i % 10 === 0)
        expect(blocks).toBe(TOTAL_EVENTS / 10);
    });
});
