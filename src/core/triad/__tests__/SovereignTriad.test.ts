import { SovereignTriad } from '../SovereignTriad';
import { DalionEventBus } from '../../bus/DalionEventBus';
import { EpistemicSignal } from '../../../types/omega';

const signal = (tier: 'TX.Ω' | 'TE.Ω', event_id: string, target_ip: string, confidence = 0.95): EpistemicSignal => ({
    tier, agentId: tier, event_id, timestamp: '', confidence, entropy: 0, evidence: { event_id, target_ip },
} as EpistemicSignal);

test('correlates signals by event and host and discards weak pairs', async () => {
    const bus = new DalionEventBus();
    const consensus = jest.fn();
    bus.subscribe('OMEGA_CONSENSUS', consensus);
    const triad = new SovereignTriad(bus);
    await triad.registerSignal(signal('TX.Ω', 'a', '10.0.0.1'));
    await triad.registerSignal(signal('TE.Ω', 'b', '10.0.0.2'));
    expect(consensus).not.toHaveBeenCalled();
    await triad.registerSignal(signal('TE.Ω', 'a', '10.0.0.1', 0.1));
    await triad.registerSignal(signal('TE.Ω', 'a', '10.0.0.1'));
    expect(consensus).not.toHaveBeenCalled();
    await triad.registerSignal(signal('TX.Ω', 'a', '10.0.0.1'));
    expect(consensus).toHaveBeenCalledTimes(1);
    expect(consensus).toHaveBeenCalledWith(expect.objectContaining({ target: '10.0.0.1' }));
});
