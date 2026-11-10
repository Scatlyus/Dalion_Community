import { ArqosBridge } from '../ArqosBridge';
import { DalionEventBus } from '../../bus/DalionEventBus';
import { StrategicDecision } from '../../../agents/d12_rottweiler/types';
import { DecisionRecord } from '../../../types/omega';

// ── Mock do PipelineCore (substitui o Arqos real nos testes) ─────────────────

const makeBlockDecision = (action: 'BLOCK' | 'ISOLATE_HOST' | 'QUARANTINE' | 'MONITOR' | 'ALLOW' = 'BLOCK'): StrategicDecision => ({
    action,
    target: '192.0.2.10',
    reason: 'Test decision',
    priority: 90,
    source_signals: {
        d2: { anomaly_score: 85, risk_level: 'high' },
        d3: { threat_score: 75, reputation: 'malicious', confidence: 0.9 },
    },
    timestamp: new Date().toISOString(),
});

const makeOmegaRecord = (): DecisionRecord => ({
    id: 'Ω-test-001',
    policy: 'NET_EGRESS_TO_MALICIOUS_IP',
    action: 'BLOCK_IP',
    target: '10.0.0.1',
    severity: 'CRITICAL',
    consensus: true,
    timestamp: new Date().toISOString(),
});

// Mock de sucesso do PipelineCore
const makePipelineMock = (fail = false, partial = false) => ({
    executePlan: fail
        ? jest.fn().mockRejectedValue(new Error('Simulated tool failure'))
        : jest.fn().mockResolvedValue({
            plan_id: 'test-plan',
            success: !partial,
            outputs: ['ok'],
            total_duration_ms: 50,
            tools_executed: 1,
            tools_failed: partial ? 1 : 0,
            errors: partial ? ['partial failure'] : undefined,
        }),
});

// ── Testes ────────────────────────────────────────────────────────────────────

describe('ArqosBridge', () => {
    let bus: DalionEventBus;
    let bridge: ArqosBridge;

    afterEach(() => {
        bridge?.dispose();
        bus?.clear();
    });

    describe('D12_DECISION → Arqos enforce', () => {
        it('rejects an unknown enforcement target', () => {
            const pipeline = makePipelineMock();
            bus = new DalionEventBus();
            bridge = new ArqosBridge(pipeline, bus);
            const result = jest.fn();
            bus.subscribe('ARQOS_TOOL_RESULT', result);
            bus.publish({ type: 'D12_DECISION', payload: { ...makeBlockDecision(), target: 'unknown' } });
            expect(pipeline.executePlan).not.toHaveBeenCalled();
            expect(result).toHaveBeenCalledWith(expect.objectContaining({ ok: false, error: expect.objectContaining({ code: 'INVALID_TARGET' }) }));
        });
        it('deve executar plano no Arqos quando D12 decide BLOCK', async () => {
            const pipeline = makePipelineMock();
            bus = new DalionEventBus();
            bridge = new ArqosBridge(pipeline as any, bus);

            bus.publish({ type: 'D12_DECISION', payload: makeBlockDecision('BLOCK') });

            // Aguarda async subscriptions
            await Promise.resolve();
            await Promise.resolve();

            expect(pipeline.executePlan).toHaveBeenCalledTimes(1);
            expect(pipeline.executePlan).toHaveBeenCalledWith(
                expect.objectContaining({
                    sequence: expect.arrayContaining([
                        expect.objectContaining({ tool_name: 'dalion.enforce', tool_input: expect.objectContaining({ target: '192.0.2.10' }) })
                    ])
                })
            );
        });

        it('deve executar plano para ISOLATE_HOST e QUARANTINE', async () => {
            for (const action of ['ISOLATE_HOST', 'QUARANTINE'] as const) {
                const pipeline = makePipelineMock();
                bus = new DalionEventBus();
                bridge = new ArqosBridge(pipeline as any, bus);

                bus.publish({ type: 'D12_DECISION', payload: makeBlockDecision(action) });
                await Promise.resolve(); await Promise.resolve();

                expect(pipeline.executePlan).toHaveBeenCalledTimes(1);
                bridge.dispose();
            }
        });

        it('NÃO deve chamar o Arqos para ações passivas (MONITOR e ALLOW)', async () => {
            for (const action of ['MONITOR', 'ALLOW'] as const) {
                const pipeline = makePipelineMock();
                bus = new DalionEventBus();
                bridge = new ArqosBridge(pipeline as any, bus);

                bus.publish({ type: 'D12_DECISION', payload: makeBlockDecision(action) });
                await Promise.resolve(); await Promise.resolve();

                expect(pipeline.executePlan).not.toHaveBeenCalled();
                bridge.dispose();
            }
        });
    });

    describe('OMEGA_CONSENSUS → Arqos audit_log', () => {
        it('deve executar plano de auditoria quando Ω emite consenso', async () => {
            const pipeline = makePipelineMock();
            bus = new DalionEventBus();
            bridge = new ArqosBridge(pipeline as any, bus);

            bus.publish({ type: 'OMEGA_CONSENSUS', payload: makeOmegaRecord() });
            await Promise.resolve(); await Promise.resolve();

            expect(pipeline.executePlan).toHaveBeenCalledWith(
                expect.objectContaining({
                    sequence: expect.arrayContaining([
                        expect.objectContaining({ tool_name: 'dalion.audit_log' })
                    ])
                })
            );
        });
    });

    describe('ARQOS_TOOL_RESULT — publicação no bus', () => {
        it('deve publicar ARQOS_TOOL_RESULT com ok=true após execução bem sucedida', async () => {
            const pipeline = makePipelineMock();
            bus = new DalionEventBus();
            bridge = new ArqosBridge(pipeline as any, bus);

            const resultHandler = jest.fn();
            bus.subscribe('ARQOS_TOOL_RESULT', resultHandler);

            bus.publish({ type: 'D12_DECISION', payload: makeBlockDecision('BLOCK') });
            await Promise.resolve(); await Promise.resolve();

            expect(resultHandler).toHaveBeenCalledWith(
                expect.objectContaining({ ok: true, tool: 'dalion.enforce' })
            );
        });

        it('deve publicar ARQOS_TOOL_RESULT com ok=false quando Arqos lança exceção', async () => {
            const pipeline = makePipelineMock(true); // mock de FALHA
            bus = new DalionEventBus();
            bridge = new ArqosBridge(pipeline as any, bus);

            const resultHandler = jest.fn();
            bus.subscribe('ARQOS_TOOL_RESULT', resultHandler);

            bus.publish({ type: 'D12_DECISION', payload: makeBlockDecision('BLOCK') });
            await Promise.resolve(); await Promise.resolve();

            expect(resultHandler).toHaveBeenCalledWith(
                expect.objectContaining({
                    ok: false,
                    error: expect.objectContaining({ code: 'ARQOS_BRIDGE_ERROR' })
                })
            );
        });

        it('deve publicar ARQOS_TOOL_RESULT com ok=false para erros parciais', async () => {
            const pipeline = makePipelineMock(false, true); // partial failure
            bus = new DalionEventBus();
            bridge = new ArqosBridge(pipeline as any, bus);

            const resultHandler = jest.fn();
            bus.subscribe('ARQOS_TOOL_RESULT', resultHandler);

            bus.publish({ type: 'D12_DECISION', payload: makeBlockDecision('BLOCK') });
            await Promise.resolve(); await Promise.resolve();

            expect(resultHandler).toHaveBeenCalledWith(
                expect.objectContaining({ ok: false })
            );
        });
    });

    describe('Lifecycle — dispose()', () => {
        it('deve parar de processar eventos após dispose()', async () => {
            const pipeline = makePipelineMock();
            bus = new DalionEventBus();
            bridge = new ArqosBridge(pipeline as any, bus);

            bridge.dispose();

            bus.publish({ type: 'D12_DECISION', payload: makeBlockDecision('BLOCK') });
            await Promise.resolve(); await Promise.resolve();

            expect(pipeline.executePlan).not.toHaveBeenCalled();
        });
    });
});
