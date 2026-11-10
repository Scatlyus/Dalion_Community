import { ThreatClassifier } from '../classifier';
import { ThreatType } from '../types';
import { EnrichedIOC } from '../../d3_espionagem/types';

const ioc = (ioc_value: string, ioc_type: 'url' | 'domain'): EnrichedIOC => ({
    ioc_value, ioc_type, is_anomaly: false, threat_score: 0, confidence: 0.9,
    reputation: 'clean', last_enriched: '', enrichment: {}, tags: [],
    event: { event_id: 'test', timestamp: '', log_source_id: 'proxy', source_ip: '10.0.0.1', action: 'http_request', status: 'allowed', severity: 'low', message: '' },
});

test.each(['https://cdn.jsdelivr.net', 'https://www.microsoft.com'])('does not treat the URL scheme in %s as a DGA label', async value => {
    const classifier = new ThreatClassifier();
    expect((await classifier.classify(ioc(value, 'url'))).threat_type).toBe(ThreatType.CLEAN);
    expect((await classifier.classify(ioc(value, 'domain'))).threat_type).toBe(ThreatType.CLEAN);
});

test('continues to detect a DGA-like domain', async () => {
    expect((await new ThreatClassifier().classify(ioc('xk4jz9mq2rp.example', 'domain'))).threat_type).toBe(ThreatType.C2);
});
