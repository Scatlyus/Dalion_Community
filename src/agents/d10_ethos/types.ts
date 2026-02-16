import { EnrichedIOC } from '../d3_espionagem/types';

export enum ThreatType {
    PHISHING = 'phishing',
    RANSOMWARE = 'ransomware',
    APT = 'apt',
    C2 = 'c2',
    MALWARE = 'malware',
    SUSPICIOUS = 'suspicious',
    CLEAN = 'clean',
    UNKNOWN = 'unknown'
}

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface ClassificationResult {
    threat_type: ThreatType;
    mitre_tactics: string[]; // TIDs like TA0001
    mitre_techniques: string[]; // TIDs like T1566
    confidence: number;
    severity: Severity;
    recommended_action: 'block' | 'quarantine' | 'monitor' | 'allow' | 'isolate_host';
    tags: string[];
}

export interface D10Config {
    confidence_threshold: number;
    auto_escalate_critical: boolean;
}

export interface ClassificationRule {
    name: string;
    description: string;
    check: (enriched: EnrichedIOC) => Promise<boolean> | boolean;
    result: Partial<ClassificationResult>;
}
