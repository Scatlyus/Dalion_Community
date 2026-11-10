import { DalionAttackGraph } from '../agents/d9_attackgraph';
import { MITREPhase } from '../agents/d9_attackgraph/types';
import { SecurityEvent } from '../agents/d2_sentinela/types';
import { DalionDiplomacia } from '../agents/d6_diplomacia';
import { DalionPsySec } from '../agents/d7_psysec';
import { IntentType } from '../agents/d7_psysec/types';
import { DalionAfterAction } from '../agents/d11_afteraction';
import { PipelineContext } from '../agents/d11_afteraction/types';
import { ThreatType } from '../agents/d10_ethos/types';
import { ComplianceValidationResult } from '../agents/d5_artilharia/types';

const event = (id: string): SecurityEvent => ({ event_id: id, timestamp: '', log_source_id: 'test', source_ip: '192.0.2.1', action: 'test', status: 'success', severity: 'low', message: '' });

test('attack graph retains repeated phases but ignores replay of the same event', async () => {
    const graph = new DalionAttackGraph();
    await graph.addEvent(event('1'), MITREPhase.EXECUTION);
    await graph.addEvent(event('2'), MITREPhase.PERSISTENCE);
    await graph.addEvent(event('3'), MITREPhase.EXECUTION);
    await graph.addEvent(event('3'), MITREPhase.EXECUTION);
    expect(graph.getGraph('192.0.2.1').nodes).toHaveLength(3);
    expect((await graph.getPredictions('192.0.2.1')).current_phase).toBe(MITREPhase.EXECUTION);
});

test('report uses actual compliance data and the strongest prediction', async () => {
    const compliance = [true, false, true, true].map(compliant => ({ compliant, violations: [], timestamp: '', summary: '' } as ComplianceValidationResult));
    const report = await new DalionDiplomacia().generateExecutiveReport([], compliance, [
        { current_phase: MITREPhase.UNKNOWN, confidence_score: 0.2, predicted_next_steps: [] },
        { current_phase: MITREPhase.EXECUTION, confidence_score: 0.9, predicted_next_steps: [{ phase: MITREPhase.EXFILTRATION, probability: 0.9, description: '' }] },
    ]);
    expect(report.metrics).toEqual([{ name: 'Regulatory Compliance Rate', value: 75, unit: '%', trend: 'unknown' }]);
    expect(report.summary).toContain('90%');
    expect(report.summary).toContain(MITREPhase.EXFILTRATION);
    expect((await new DalionDiplomacia().generateExecutiveReport([], [], [])).metrics).toEqual([]);
});

test('does not infer espionage without known targets', () => {
    const profile = new DalionPsySec().profileActor([event('1'), event('2'), event('3'), event('4')]);
    expect(profile.intent).toBe(IntentType.UNKNOWN);
    expect(profile.focus).toBe('wide');
});

test('successful passive actions do not reinforce malware rules', () => {
    const context = { execution: { success: true }, classification: { threat_type: ThreatType.MALWARE, confidence: 0.95 }, decision: { action: 'ALLOW' }, enriched: { tags: ['test'] } } as unknown as PipelineContext;
    const agent = new DalionAfterAction();
    expect(agent.analyze(context).feedback_type).toBe('NEUTRAL');
    expect(agent.analyze({ ...context, decision: { ...context.decision, action: 'BLOCK' } }).feedback_type).toBe('POSITIVE_REINFORCEMENT');
});
