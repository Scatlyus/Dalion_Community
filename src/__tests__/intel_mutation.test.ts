import { DalionThreatIntel } from '../agents/d8_threatintel';
import { EnrichedIOC } from '../agents/d3_espionagem/types';
import { MutationLab } from '../agents/d5_artilharia/MutationLab';
import { ComplianceFramework, ComplianceRule } from '../agents/d5_artilharia/types';
import { SecurityEvent } from '../agents/d2_sentinela/types';

const event: SecurityEvent = { event_id: '1', timestamp: '', log_source_id: 'test', source_ip: '192.0.2.1', action: 'test', status: 'success', severity: 'low', message: 'secret' };
const ioc = (ioc_value: string, threat_score: number): EnrichedIOC => ({ ioc_type: 'domain', ioc_value, event, is_anomaly: true, enrichment: {}, threat_score, confidence: 0.5, reputation: 'unknown', last_enriched: '' });

test('aggregate only combines reports for the same IOC', () => {
    const d8 = new DalionThreatIntel();
    expect(d8.aggregate([ioc('a.example', 100), ioc('a.example', 0)].map((item, i) => ({ ...item, confidence: i ? 0.25 : 0.75 }))).weighted_score).toBe(75);
    expect(() => d8.aggregate([ioc('a.example', 100), ioc('b.example', 0)])).toThrow('different IOCs');
    expect(() => d8.aggregate([ioc('a.example', 100), { ...ioc('a.example', 0), ioc_type: 'url' }])).toThrow('different IOCs');
});

test('mutation tests count violations and regression correctly', async () => {
    const rule: ComplianceRule = { id: 'test', name: 'test', description: '', framework: ComplianceFramework.LGPD, severity: 'high', check: async item => item.message === 'secret' };
    const lab = new MutationLab();
    const data = [event, { ...event, event_id: '2', message: 'safe' }];
    expect(await lab.testRule(rule, data)).toEqual(expect.objectContaining({ total_events: 2, violations_detected: 1, pass_rate: 50 }));
    expect((await lab.runRegression([rule], data)).total_violations).toBe(1);
});
