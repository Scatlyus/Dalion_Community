import { DalionOrchestrator, PipelineResult } from '../DalionOrchestrator';
import { DalionEventBus } from '../../bus/DalionEventBus';
import { SovereignTriad } from '../../triad/SovereignTriad';
import { SecurityEvent } from '../../../agents/d2_sentinela/types';
import { ThreatType } from '../../../agents/d10_ethos/types';

// ── Mocks ─────────────────────────────────────────────────────────────────────

const makeEvent = (overrides: Partial<SecurityEvent> = {}): SecurityEvent => ({
    timestamp: new Date().toISOString(),
    event_id: 'EVT-001',
    log_source_id: 'test',
    source_ip: '192.168.1.100',
    action: 'login',
    status: 'failure',
    severity: 'high',
    message: 'Failed login attempt',
    ...overrides,
});

const makeD2Mock = (score = 75, anomaly = true) => ({
    analyze: jest.fn().mockResolvedValue({
        anomaly,
        reason: 'Brute force detected',
        anomaly_score: score,
        risk_level: score >= 90 ? 'critical' : score >= 75 ? 'high' : 'medium',
        tags: ['brute_force'],
        rules_processed: 5,
    }),
});

const makeD3Mock = (fail = false) => ({
    enrich: fail
        ? jest.fn().mockRejectedValue(new Error('VirusTotal API timeout'))
        : jest.fn().mockResolvedValue({
            enriched_iocs: [{
                ioc_type: 'IP',
                ioc_value: '192.168.1.100',
                is_anomaly: true,
                event: makeEvent(),
                enrichment: {},
                threat_score: 70,
                confidence: 0.8,
                reputation: 'suspicious',
                last_enriched: new Date().toISOString(),
            }],
        }),
});

const makeD10Mock = (fail = false) => ({
    classify: fail
        ? jest.fn().mockRejectedValue(new Error('Classifier internal error'))
        : jest.fn().mockResolvedValue({
            threat_type: ThreatType.MALWARE,
            mitre_tactics: ['TA0001'],
            mitre_techniques: ['T1566'],
            confidence: 0.85,
            severity: 'high',
            recommended_action: 'block',
            tags: ['malware'],
        }),
});

const makeD12Mock = () => ({
    decide: jest.fn().mockReturnValue({
        action: 'BLOCK',
        reason: 'Combined risk score',
        priority: 90,
        source_signals: { d2: { anomaly_score: 75, risk_level: 'high' }, d3: { threat_score: 70, reputation: 'suspicious', confidence: 0.8 } },
        timestamp: new Date().toISOString(),
    }),
});

const makeTriadMock = () => ({
    registerSignal: jest.fn().mockResolvedValue(undefined),
});

// ── Helpers ───────────────────────────────────────────────────────────────────

const buildOrchestrator = (overrides: {
    d2?: ReturnType<typeof makeD2Mock>;
    d3?: ReturnType<typeof makeD3Mock>;
    d10?: ReturnType<typeof makeD10Mock>;
    d12?: ReturnType<typeof makeD12Mock>;
    triad?: ReturnType<typeof makeTriadMock>;
    omegaThreshold?: number;
} = {}) => {
    const bus = new DalionEventBus();
    const orchestrator = new DalionOrchestrator(
        overrides.d2 ?? makeD2Mock() as any,
        overrides.d3 ?? makeD3Mock() as any,
        overrides.d10 ?? makeD10Mock() as any,
        overrides.d12 ?? makeD12Mock() as any,
        overrides.triad ?? makeTriadMock() as any,
        bus,
        { omegaThreshold: overrides.omegaThreshold ?? 80 }
    );
    return { orchestrator, bus };
};

// ── Testes ────────────────────────────────────────────────────────────────────

describe('DalionOrchestrator', () => {

    describe('Pipeline completo (happy path)', () => {
        it('deve retornar StrategicDecision com action definida', async () => {
            const { orchestrator } = buildOrchestrator();
            const result = await orchestrator.process(makeEvent());

            expect(result.decision).toBeDefined();
            expect(result.decision.action).toBe('BLOCK');
            expect(result.errors).toHaveLength(0);
        });

        it('deve emitir eventos no bus na ordem correta', async () => {
            const { orchestrator, bus } = buildOrchestrator();
            const emitted: string[] = [];

            bus.subscribe('D2_DETECTION', () => { emitted.push('D2_DETECTION'); });
            bus.subscribe('D3_ENRICHMENT', () => { emitted.push('D3_ENRICHMENT'); });
            bus.subscribe('D10_CLASSIFICATION', () => { emitted.push('D10_CLASSIFICATION'); });
            bus.subscribe('D12_DECISION', () => { emitted.push('D12_DECISION'); });

            await orchestrator.process(makeEvent());

            expect(emitted).toEqual(['D2_DETECTION', 'D3_ENRICHMENT', 'D10_CLASSIFICATION', 'D12_DECISION']);
        });

        it('deve fornecer d2_score correto no resultado', async () => {
            const d2 = makeD2Mock(92, true);
            const { orchestrator } = buildOrchestrator({ d2 });
            const result = await orchestrator.process(makeEvent());

            expect(result.d2_score).toBe(92);
        });
    });

    describe('Error boundary — D3 falha', () => {
        it('deve continuar o pipeline com IOC de fallback quando D3 lança erro', async () => {
            const d3 = makeD3Mock(true);
            const { orchestrator } = buildOrchestrator({ d3 });
            const result = await orchestrator.process(makeEvent());

            expect(result.decision).toBeDefined();
            expect(result.errors).toHaveLength(1);
            expect(result.errors[0]).toContain('D3_ERROR');
        });

        it('deve publicar D3_ERROR no bus quando D3 falha', async () => {
            const d3 = makeD3Mock(true);
            const { orchestrator, bus } = buildOrchestrator({ d3 });

            const d3ErrorHandler = jest.fn();
            bus.subscribe('D3_ERROR', d3ErrorHandler);

            await orchestrator.process(makeEvent());

            expect(d3ErrorHandler).toHaveBeenCalledTimes(1);
            expect(d3ErrorHandler).toHaveBeenCalledWith(
                expect.objectContaining({ source_ip: '192.168.1.100' })
            );
        });
    });

    describe('Error boundary — D10 falha', () => {
        it('deve continuar o pipeline sem classificação taxonômica quando D10 falha', async () => {
            const d10 = makeD10Mock(true);
            const { orchestrator } = buildOrchestrator({ d10 });
            const result = await orchestrator.process(makeEvent());

            expect(result.decision).toBeDefined();
            expect(result.errors).toHaveLength(1);
            expect(result.errors[0]).toContain('D10_ERROR');
        });
    });

    describe('SovereignTriad Ω', () => {
        it('deve acionar o Triad quando score >= omegaThreshold', async () => {
            const d2 = makeD2Mock(85, true);
            const triad = makeTriadMock();
            const { orchestrator } = buildOrchestrator({ d2, triad, omegaThreshold: 80 });

            const result = await orchestrator.process(makeEvent());

            expect(result.omega_triggered).toBe(true);
            expect(triad.registerSignal).toHaveBeenCalledTimes(2); // TX.Ω e TE.Ω
        });

        it('NÃO deve acionar o Triad quando score < omegaThreshold', async () => {
            const d2 = makeD2Mock(70, true);
            const triad = makeTriadMock();
            const { orchestrator } = buildOrchestrator({ d2, triad, omegaThreshold: 80 });

            const result = await orchestrator.process(makeEvent());

            expect(result.omega_triggered).toBe(false);
            expect(triad.registerSignal).not.toHaveBeenCalled();
        });

        it('omegaThreshold deve ser configurável', async () => {
            const d2 = makeD2Mock(60, true);
            const triad = makeTriadMock();
            // Threshold baixo — score 60 deve acionar o Triad
            const { orchestrator } = buildOrchestrator({ d2, triad, omegaThreshold: 50 });

            const result = await orchestrator.process(makeEvent());

            expect(result.omega_triggered).toBe(true);
        });
    });
});
