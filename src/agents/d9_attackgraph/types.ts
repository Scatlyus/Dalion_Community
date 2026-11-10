import { SecurityEvent } from '../d2_sentinela/types';

export enum MITREPhase {
    INITIAL_ACCESS = 'Initial Access',
    EXECUTION = 'Execution',
    PERSISTENCE = 'Persistence',
    PRIVILEGE_ESCALATION = 'Privilege Escalation',
    DEFENSE_EVASION = 'Defense Evasion',
    CREDENTIAL_ACCESS = 'Credential Access',
    DISCOVERY = 'Discovery',
    LATERAL_MOVEMENT = 'Lateral Movement',
    COLLECTION = 'Collection',
    COMMAND_AND_CONTROL = 'Command and Control',
    EXFILTRATION = 'Exfiltration',
    IMPACT = 'Impact',
    UNKNOWN = 'Unknown'
}

export interface AttackNode {
    id: string; // Combined source_ip + phase/ttp
    event_id: string;
    timestamp: string;
    source_ip: string;
    phase: MITREPhase;
    ttp?: string; // MITRE Technique ID (e.g. T1566)
    description: string;
    observed: boolean;
}

export interface AttackEdge {
    fromId: string;
    toId: string;
    probability: number;
    description: string;
}

export interface PredictionResult {
    current_phase: MITREPhase;
    predicted_next_steps: Array<{
        phase: MITREPhase;
        ttp?: string;
        probability: number;
        description: string;
    }>;
    confidence_score: number;
}

export interface IAttackGraph {
    addEvent(event: SecurityEvent, phase: MITREPhase, ttp?: string): Promise<void>;
    getPredictions(sourceIp: string): Promise<PredictionResult>;
    getGraph(sourceIp: string): { nodes: AttackNode[], edges: AttackEdge[] };
}
