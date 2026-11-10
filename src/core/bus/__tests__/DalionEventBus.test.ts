import { DalionEventBus } from '../DalionEventBus';
import { DetectionResult } from '../../../agents/d2_sentinela/types';

// ── Fixtures ──────────────────────────────────────────────────────────────────

const makeDetectionResult = (score = 75): DetectionResult => ({
    anomaly: score >= 60,
    reason: 'Test anomaly',
    anomaly_score: score,
    risk_level: score >= 90 ? 'critical' : score >= 75 ? 'high' : 'medium',
    tags: ['test'],
    rules_processed: 5
});

// ── Testes ────────────────────────────────────────────────────────────────────

describe('DalionEventBus', () => {
    let bus: DalionEventBus;

    beforeEach(() => {
        bus = new DalionEventBus(); // instância fresca por teste
    });

    afterEach(() => {
        bus.clear();
    });

    // ── Publish / Subscribe básico ────────────────────────────────────────────

    it('deve chamar o subscriber quando o evento correto é publicado', () => {
        const handler = jest.fn();
        bus.subscribe('D2_DETECTION', handler);

        const payload = makeDetectionResult();
        bus.publish({ type: 'D2_DETECTION', payload });

        expect(handler).toHaveBeenCalledTimes(1);
        expect(handler).toHaveBeenCalledWith(payload);
    });

    it('não deve chamar subscriber de tipo diferente', () => {
        const handler = jest.fn();
        bus.subscribe('D12_DECISION', handler);

        bus.publish({ type: 'D2_DETECTION', payload: makeDetectionResult() });

        expect(handler).not.toHaveBeenCalled();
    });

    // ── Multi-subscriber ──────────────────────────────────────────────────────

    it('deve chamar múltiplos subscribers do mesmo tipo', () => {
        const h1 = jest.fn();
        const h2 = jest.fn();
        const h3 = jest.fn();

        bus.subscribe('D2_DETECTION', h1);
        bus.subscribe('D2_DETECTION', h2);
        bus.subscribe('D2_DETECTION', h3);

        bus.publish({ type: 'D2_DETECTION', payload: makeDetectionResult() });

        expect(h1).toHaveBeenCalledTimes(1);
        expect(h2).toHaveBeenCalledTimes(1);
        expect(h3).toHaveBeenCalledTimes(1);
    });

    it('deve chamar subscribers na ordem de registro', () => {
        const order: number[] = [];
        bus.subscribe('D2_DETECTION', () => { order.push(1); });
        bus.subscribe('D2_DETECTION', () => { order.push(2); });
        bus.subscribe('D2_DETECTION', () => { order.push(3); });

        bus.publish({ type: 'D2_DETECTION', payload: makeDetectionResult() });

        expect(order).toEqual([1, 2, 3]);
    });

    // ── Unsubscribe ───────────────────────────────────────────────────────────

    it('deve cancelar a subscrição ao chamar a função retornada', () => {
        const handler = jest.fn();
        const unsubscribe = bus.subscribe('D2_DETECTION', handler);

        bus.publish({ type: 'D2_DETECTION', payload: makeDetectionResult() });
        expect(handler).toHaveBeenCalledTimes(1);

        unsubscribe();
        bus.publish({ type: 'D2_DETECTION', payload: makeDetectionResult() });
        expect(handler).toHaveBeenCalledTimes(1); // ainda 1 — não chamou de novo
    });

    // ── Error boundaries ──────────────────────────────────────────────────────

    it('deve publicar D3_ERROR corretamente', () => {
        const handler = jest.fn();
        bus.subscribe('D3_ERROR', handler);

        bus.publish({ type: 'D3_ERROR', payload: { source_ip: '1.2.3.4', error: 'API timeout' } });

        expect(handler).toHaveBeenCalledWith({ source_ip: '1.2.3.4', error: 'API timeout' });
    });

    it('deve publicar D10_ERROR corretamente', () => {
        const handler = jest.fn();
        bus.subscribe('D10_ERROR', handler);

        bus.publish({ type: 'D10_ERROR', payload: { ioc_value: '1.2.3.4', error: 'Classifier failed' } });

        expect(handler).toHaveBeenCalledTimes(1);
    });

    // ── Diagnóstico ───────────────────────────────────────────────────────────

    it('subscriberCount deve refletir o número de handlers registrados', () => {
        expect(bus.subscriberCount('D2_DETECTION')).toBe(0);

        const unsub1 = bus.subscribe('D2_DETECTION', jest.fn());
        const unsub2 = bus.subscribe('D2_DETECTION', jest.fn());

        expect(bus.subscriberCount('D2_DETECTION')).toBe(2);

        unsub1();
        expect(bus.subscriberCount('D2_DETECTION')).toBe(1);

        unsub2();
        expect(bus.subscriberCount('D2_DETECTION')).toBe(0);
    });

    // ── Clear ─────────────────────────────────────────────────────────────────

    it('clear(type) deve remover apenas subscribers daquele tipo', () => {
        const d2Handler = jest.fn();
        const d3Handler = jest.fn();

        bus.subscribe('D2_DETECTION', d2Handler);
        bus.subscribe('D3_ENRICHMENT', d3Handler);

        bus.clear('D2_DETECTION');

        bus.publish({ type: 'D2_DETECTION', payload: makeDetectionResult() });
        expect(d2Handler).not.toHaveBeenCalled();

        // D3 não foi afetado
        expect(bus.subscriberCount('D3_ENRICHMENT')).toBe(1);
    });

    it('publish sem subscribers não deve lançar erro', () => {
        expect(() => {
            bus.publish({
                type: 'OMEGA_CONSENSUS', payload: {
                    id: 'Ω-001',
                    policy: 'TEST',
                    action: 'BLOCK_IP',
                    target: '0.0.0.0',
                    severity: 'HIGH',
                    consensus: true,
                    timestamp: new Date().toISOString()
                }
            });
        }).not.toThrow();
    });
});
