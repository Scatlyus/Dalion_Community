import { ThreatClassifier } from '../classifier';
import { ThreatType } from '../types';
import { EnrichedIOC } from '../../d3_espionagem/types';

test('does not confuse paypal with the paypa1 typo', async () => {
    const classifier = new ThreatClassifier();
    const make = (ioc_value: string): EnrichedIOC => ({
        ioc_type: 'domain', ioc_value, is_anomaly: false, threat_score: 0, confidence: 1,
        reputation: 'clean', last_enriched: '', tags: [], enrichment: {},
        event: { timestamp: '', event_id: '1', log_source_id: 'test', source_ip: '10.0.0.1', action: 'dns', status: 'success', severity: 'low', message: '' },
    });
    expect((await classifier.classify(make('paypal.com'))).threat_type).not.toBe(ThreatType.PHISHING);
    expect((await classifier.classify(make('paypa1.com'))).threat_type).toBe(ThreatType.PHISHING);
});
