import { DalionOrchestrator } from '../DalionOrchestrator';
import { DalionSentinela } from '../../../agents/d2_sentinela/index';
import { DalionRottweiler } from '../../../agents/d12_rottweiler/index';
import { SovereignTriad } from '../../triad/SovereignTriad';
import { DalionEventBus } from '../../bus/DalionEventBus';
import { ThreatType } from '../../../agents/d10_ethos/types';
import { SecurityEvent } from '../../../agents/d2_sentinela/types';

// Mock de inteligência controlada
const makeD3Mock = (threatScore: number) => ({
    enrich: jest.fn().mockImplementation(async (request) => ({
        enriched_iocs: request.iocs.map((ioc: any) => ({
            ...ioc,
            threat_score: threatScore,
            reputation: threatScore > 70 ? 'suspicious' : 'clean',
            tags: []
        }))
    }))
});

const makeD10Mock = () => ({
    classify: jest.fn().mockImplementation(async () => ({
        threat_type: ThreatType.SUSPICIOUS,
        recommended_action: 'monitor',
        severity: 'medium'
    }))
});

describe('Dalion Trajectory Tracking - Phase 9 (Cronos)', () => {
    let orchestrator: DalionOrchestrator;
    let d3Mock: any;
    const bus = new DalionEventBus();

    const createEvent = (ip: string, id: string): SecurityEvent => ({
        timestamp: new Date().toISOString(),
        event_id: id,
        log_source_id: 'test',
        source_ip: ip,
        action: 'http',
        status: 'allowed',
        severity: 'medium',
        message: 'Normal traffic',
        metadata: { http: { url: '/', hostname: 'example.com' } }
    });

    beforeEach(() => {
        d3Mock = makeD3Mock(65);
        orchestrator = new DalionOrchestrator(
            new DalionSentinela(),
            d3Mock as any,
            makeD10Mock() as any,
            new DalionRottweiler(),
            new SovereignTriad(bus),
            bus
        );
    });

    it('deve escalonar para BLOCK após 3 eventos de risco crescente (Trajetória)', async () => {
        const IP = '10.0.0.50';

        // Evento 1: Risco 65 -> EXPECT MONITOR
        d3Mock.enrich.mockImplementationOnce(async (req: any) => ({
            enriched_iocs: [{ ...req.iocs[0], threat_score: 65 }]
        }));
        const res1 = await orchestrator.process(createEvent(IP, 'evt-1'));
        console.log('Event 1 Action:', res1.decision.action);
        expect(res1.decision.action).toBe('MONITOR');

        // Evento 2: Risco 70 -> EXPECT MONITOR
        d3Mock.enrich.mockImplementationOnce(async (req: any) => ({
            enriched_iocs: [{ ...req.iocs[0], threat_score: 70 }]
        }));
        const res2 = await orchestrator.process(createEvent(IP, 'evt-2'));
        console.log('Event 2 Action:', res2.decision.action);
        expect(res2.decision.action).toBe('MONITOR');

        // Evento 3: Risco 75 -> EXPECT BLOCK (Escalonamento por Tendência)
        d3Mock.enrich.mockImplementationOnce(async (req: any) => ({
            enriched_iocs: [{ ...req.iocs[0], threat_score: 75 }]
        }));
        const res3 = await orchestrator.process(createEvent(IP, 'evt-3'));
        console.log('Event 3 Action:', res3.decision.action);

        // Se a lógica do Rottweiler estiver correta: trend = [65, 70, 75] -> isEscalating = true
        expect(res3.decision.action).toBe('BLOCK');
    });
});
