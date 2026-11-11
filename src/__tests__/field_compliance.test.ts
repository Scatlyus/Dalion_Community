import { DalionIntelCampo } from '../agents/d4_intel_campo';
import { DalionArtilharia } from '../agents/d5_artilharia';
import { MutationLab } from '../agents/d5_artilharia/MutationLab';
import { getLGPDRules } from '../agents/d5_artilharia/rules';
import { SecurityEvent } from '../agents/d2_sentinela/types';

const event = (id: string, source_ip: string, severity: SecurityEvent['severity'] = 'low'): SecurityEvent => ({
    event_id: id, source_ip, severity, timestamp: '', log_source_id: 'test', status: 'success', action: 'read', message: 'ok',
});

test('prefers distributed correlation over a larger benign subnet', () => {
    const field = new DalionIntelCampo();
    const events = [event('1', '10.0.0.1'), event('2', '10.0.0.1'), event('3', '10.0.0.1'), event('4', '10.0.0.1'), event('5', '10.0.1.1', 'high'), event('6', '10.0.1.2'), event('7', '10.0.1.2')];
    expect(field.analyzeField(events)).toEqual(expect.objectContaining({ subnet: '10.0.1', correlation_detected: true }));
    expect(field.analyzeField([event('1', '10.0.0.1', 'high'), event('2', '10.0.0.1'), event('3', '10.0.0.1')])?.correlation_detected).toBe(false);
    expect(field.analyzeField([event('1', '2001:db8::1')])).toBeUndefined();
});

test('requires evidence of unauthorized access to a sensitive path', async () => {
    const d5 = new DalionArtilharia();
    const base = { ...event('1', '10.0.0.1'), file_path: '/data/pii/customer.json' };
    expect((await d5.validate(base)).compliant).toBe(true);
    expect((await d5.validate({ ...base, metadata: { authorized: false } })).violations.map(v => v.id)).toContain('RL-LGPD-002');
    expect((await d5.validate({ ...base, file_path: '/data/pii-backup', metadata: { authorized: false } })).compliant).toBe(true);
    expect((await d5.validate({ ...base, file_path: '/etc/passwd-backup', metadata: { authorized: false } })).compliant).toBe(true);
});

test('mutation report never reproduces a message or event ID containing sensitive data', async () => {
    const secret = 'person@example.com';
    const report = await new MutationLab().testRule(getLGPDRules().get('RL-LGPD-001')!, [{ ...event(secret, '10.0.0.1'), message: secret }]);
    expect(report.violations_detected).toBe(1);
    expect(JSON.stringify(report)).not.toContain(secret);
});
