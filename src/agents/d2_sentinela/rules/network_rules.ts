import { DetectionRule } from '../types';

/**
 * C2, network traffic, and communication pattern detection rules
 */
export function getNetworkRules(): Map<string, DetectionRule> {
    const rules = new Map<string, DetectionRule>();

    // Rule 4: Suspicious Low Volume Flow (Beaconing)
    rules.set('suspicious_low_volume_flow', {
        name: 'suspicious_low_volume_flow',
        description: 'Potential C2 beaconing pattern (low volume, fixed size)',
        impact_score: 65,
        check: async (event) => {
            const eve = event.metadata;
            if (!eve || eve.event_type !== 'flow' || !eve.flow) return false;

            const f = eve.flow;
            const lowVolume = f.pkts_toserver <= 3 && f.pkts_toclient <= 3;
            const smallPayload = f.bytes_toserver < 500 && f.bytes_toclient < 500;
            return lowVolume && smallPayload && !f.alerted;
        }
    });

    // Rule 9: C2 Beacon Detection (Variance Analysis)
    rules.set('c2_communication_pattern', {
        name: 'c2_communication_pattern',
        description: 'Detect regular C2 beaconing behavior via variance analysis',
        impact_score: 95,
        check: async (event, history) => {
            const recent = history.get(event.source_ip) || [];
            if (recent.length < 5) return false;

            const intervals = [];
            for (let i = 1; i < recent.length; i++) {
                const diff = new Date(recent[i].timestamp).getTime() - new Date(recent[i - 1].timestamp).getTime();
                if (diff > 0) intervals.push(diff);
            }

            if (intervals.length < 4) return false;

            const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
            const variance = intervals.map(i => Math.abs(i - avgInterval)).reduce((a, b) => a + b) / intervals.length;

            // Low variance (<20% of interval) indicates beaconing
            const isRegular = variance < avgInterval * 0.2;
            return isRegular;
        }
    });

    // Rule 20: DGA-like Domain (Entropy Refined)
    rules.set('dga_like_domain', {
        name: 'dga_like_domain',
        description: 'High entropy domain name detected (DGA)',
        impact_score: 70,
        check: async (event) => {
            const context = (event as any).context || {};
            const domain = context.domain || '';
            if (domain.length < 8) return false;
            const hostname = domain.split('.')[0];
            return calculateEntropy(hostname) > 3.1;
        }
    });

    return rules;
}

// Helper function
function calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    const counts: Record<string, number> = {};
    for (const char of str) {
        counts[char] = (counts[char] || 0) + 1;
    }
    return Object.values(counts).reduce((sum, count) => {
        const p = count / len;
        return sum - p * Math.log2(p);
    }, 0);
}
