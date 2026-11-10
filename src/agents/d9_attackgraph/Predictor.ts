import { MITREPhase, PredictionResult, AttackNode } from './types';

export class AttackPredictor {
    // Matriz de transição simplificada baseada na Kill Chain do MITRE
    private static TRANSITION_MAP: Record<MITREPhase, Array<{ phase: MITREPhase, prob: number, desc: string }>> = {
        [MITREPhase.INITIAL_ACCESS]: [
            { phase: MITREPhase.EXECUTION, prob: 0.72, desc: 'Execution via malicious payload' },
            { phase: MITREPhase.PERSISTENCE, prob: 0.15, desc: 'Direct persistence establishment' },
            { phase: MITREPhase.DISCOVERY, prob: 0.10, desc: 'Neighbor reconnaissance' }
        ],
        [MITREPhase.EXECUTION]: [
            { phase: MITREPhase.PERSISTENCE, prob: 0.68, desc: 'Establishing persistence mechanisms' },
            { phase: MITREPhase.DEFENSE_EVASION, prob: 0.55, desc: 'Masking execution traces' },
            { phase: MITREPhase.CREDENTIAL_ACCESS, prob: 0.40, desc: 'Dumping local credentials' }
        ],
        [MITREPhase.PERSISTENCE]: [
            { phase: MITREPhase.PRIVILEGE_ESCALATION, prob: 0.65, desc: 'Elevating to administrative/SYSTEM' },
            { phase: MITREPhase.LATERAL_MOVEMENT, prob: 0.50, desc: 'Pivot to other subnetworks' }
        ],
        [MITREPhase.PRIVILEGE_ESCALATION]: [
            { phase: MITREPhase.CREDENTIAL_ACCESS, prob: 0.80, desc: 'High-privilege credential extraction' },
            { phase: MITREPhase.EXFILTRATION, prob: 0.30, desc: 'Direct exfiltration of admin data' }
        ],
        [MITREPhase.CREDENTIAL_ACCESS]: [
            { phase: MITREPhase.LATERAL_MOVEMENT, prob: 0.85, desc: 'Lateral movement using stolen credentials' },
            { phase: MITREPhase.COLLECTION, prob: 0.45, desc: 'Data collection for exfiltration' }
        ],
        [MITREPhase.LATERAL_MOVEMENT]: [
            { phase: MITREPhase.DISCOVERY, prob: 0.90, desc: 'Reconnaissance on new target' },
            { phase: MITREPhase.COLLECTION, prob: 0.60, desc: 'Collecting data from pivot target' }
        ],
        [MITREPhase.DISCOVERY]: [
            { phase: MITREPhase.LATERAL_MOVEMENT, prob: 0.70, desc: 'Target identified, preparing pivot' },
            { phase: MITREPhase.COLLECTION, prob: 0.50, desc: 'Target identified, gathering data' }
        ],
        [MITREPhase.COLLECTION]: [
            { phase: MITREPhase.COMMAND_AND_CONTROL, prob: 0.80, desc: 'Contacting C2 for exfiltration' },
            { phase: MITREPhase.EXFILTRATION, prob: 0.75, desc: 'Initiating data transfer' }
        ],
        [MITREPhase.COMMAND_AND_CONTROL]: [
            { phase: MITREPhase.EXFILTRATION, prob: 0.90, desc: 'Exfiltrating data through C2 channel' },
            { phase: MITREPhase.IMPACT, prob: 0.40, desc: 'Executing final impact actions' }
        ],
        [MITREPhase.EXFILTRATION]: [
            { phase: MITREPhase.IMPACT, prob: 0.60, desc: 'Data exfiltrated, proceeding to impact' }
        ],
        [MITREPhase.DEFENSE_EVASION]: [
            { phase: MITREPhase.CREDENTIAL_ACCESS, prob: 0.50, desc: 'Safe credential harvesting' },
            { phase: MITREPhase.LATERAL_MOVEMENT, prob: 0.40, desc: 'Silent pivoting' }
        ],
        [MITREPhase.IMPACT]: [],
        [MITREPhase.UNKNOWN]: [
            { phase: MITREPhase.INITIAL_ACCESS, prob: 0.20, desc: 'Potential new attack entry' }
        ]
    };

    /**
     * Prediz os próximos passos baseados no último nó observado.
     */
    predict(lastNode?: AttackNode): PredictionResult {
        if (!lastNode) {
            return {
                current_phase: MITREPhase.UNKNOWN,
                predicted_next_steps: [],
                confidence_score: 0
            };
        }

        const predictions = AttackPredictor.TRANSITION_MAP[lastNode.phase] || [];

        return {
            current_phase: lastNode.phase,
            predicted_next_steps: predictions.map(p => ({
                phase: p.phase,
                probability: p.prob,
                description: p.desc
            })),
            confidence_score: predictions.length > 0 ? Math.max(...predictions.map(p => p.prob)) : 0
        };
    }
}
