import { DalionRottweiler } from '../index';
import { EnrichedIOC } from '../../d3_espionagem/types';
import { DetectionResult } from '../../d2_sentinela/types';
import { HostContext } from '../../../core/orchestrator/DalionStateContext';

test('critical alerts isolate the source host even when risk is rising', () => {
    const d2: DetectionResult = { anomaly: true, anomaly_score: 90, risk_level: 'critical', reason: '', tags: [] };
    const d3: EnrichedIOC = {
        ioc_type: 'IP', ioc_value: '203.0.113.5', is_anomaly: true, threat_score: 90,
        confidence: 1, reputation: 'malicious', last_enriched: '', enrichment: {},
        event: { timestamp: '', event_id: '1', log_source_id: 'test', source_ip: '10.0.0.1', action: 'suricata_alert', status: 'success', severity: 'critical', message: '' },
    };
    const decision = new DalionRottweiler().decide(d2, d3, undefined, { risk_score_trend: [50, 70] } as HostContext);
    expect(decision.action).toBe('ISOLATE_HOST');
    expect(decision.target).toBe('10.0.0.1');
});
