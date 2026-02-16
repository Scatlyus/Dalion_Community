import { DetectionResult } from '../d2_sentinela/types';
import { EnrichedIOC } from '../d3_espionagem/types';
import { ClassificationResult, ThreatType } from '../d10_ethos/types';
import { StrategicDecision, SecurityAction, SDEConfig } from './types';

export class DalionRottweiler {
    private config: SDEConfig;

    constructor(config?: Partial<SDEConfig>) {
        this.config = {
            thresholds: config?.thresholds || {
                critical_risk: 90,
                high_threat: 85,
                min_confidence: 0.7
            },
            default_action: config?.default_action || 'MONITOR'
        };
    }

    /**
     * Strategic decision matrix
     * Orchestrates D2 (Local), D3 (Global) and D10 (Taxonomic) signals
     */
    public decide(d2: DetectionResult, d3: EnrichedIOC, d10?: ClassificationResult): StrategicDecision {
        const timestamp = new Date().toISOString();

        // 1. Determine action based on hierarchical signals
        const action = this.arbitrateAction(d2, d3, d10);

        // 2. Build decision object following StrategicDecision interface
        return {
            action,
            reason: this.generateReason(action, d2, d3, d10),
            priority: this.calculatePriority(action, d2, d3),
            source_signals: {
                d2: {
                    anomaly_score: d2.anomaly_score,
                    risk_level: d2.risk_level
                },
                d3: {
                    threat_score: d3.threat_score || 0,
                    reputation: 'unknown', // D3 reputation legacy
                    confidence: d3.confidence || 0.5
                },
                d10: d10 ? {
                    threat_type: d10.threat_type,
                    mitre_tactics: d10.mitre_tactics,
                    severity: d10.severity
                } : undefined
            },
            timestamp
        };
    }

    private arbitrateAction(d2: DetectionResult, d3: EnrichedIOC, d10?: ClassificationResult): SecurityAction {
        const localRisk = d2.anomaly_score;
        const globalRisk = d3.threat_score || 0;
        const threatType = d10?.threat_type || ThreatType.UNKNOWN;
        const psysec = d3.psysec;

        // EMERGENCY: Ransomware, Espionage, or Elite Attacker
        const isHighValueIntent = psysec?.profile?.intent === 'ESPIONAGE' || psysec?.profile?.skill_level === 'ELITE' || psysec?.profile?.skill_level === 'ADVANCED';

        if (threatType === ThreatType.RANSOMWARE || (d2.tags || []).includes('shadow_copy_deletion') || isHighValueIntent) {
            return 'ISOLATE_HOST';
        }

        // HIGH CONFIDENCE THREATS: Phishing, C2, APT or high score malware
        if (threatType === ThreatType.PHISHING || threatType === ThreatType.C2 || threatType === ThreatType.APT) {
            return 'BLOCK';
        }

        const tags = [...(d2.tags || []), ...(d3.tags || [])];
        const highConfidenceMalware = threatType === ThreatType.MALWARE && (d10?.confidence || 0) >= 0.8;
        const hasBehavioralTag = tags.includes('suspicious_download_exe') || tags.includes('browser_to_shell') || tags.includes('registry_persistence');
        const isRealTarget = !d3.ioc_value.startsWith('event:');

        if (highConfidenceMalware && hasBehavioralTag && isRealTarget) {
            return 'QUARANTINE';
        }

        if (threatType === ThreatType.MALWARE && (localRisk > 80 || globalRisk > 80)) {
            return 'BLOCK'; // Fallback to BLOCK for lower confidence malware
        }

        // HEURISTIC OVERRIDE: If D10 is silent but D2 is critical
        if (d2.risk_level === 'critical' && d2.anomaly) {
            return 'BLOCK';
        }

        // MIXED RISK: High risk but not definitively malicious
        if (localRisk > 70 || globalRisk > 70) {
            if (d2.anomaly) return 'BLOCK'; // Preemptive block
            return 'MONITOR';
        }

        // CLEAN/LOW RISK
        if (threatType === ThreatType.CLEAN && localRisk < 20) {
            return 'ALLOW';
        }

        return this.config.default_action;
    }

    private generateReason(action: SecurityAction, d2: DetectionResult, d3: EnrichedIOC, d10?: ClassificationResult): string {
        if (d10 && d10.threat_type !== ThreatType.UNKNOWN && d10.threat_type !== ThreatType.CLEAN) {
            return `Taxonomic Override: ${d10.threat_type.toUpperCase()} confirmed by Ethos`;
        }
        if (d2.risk_level === 'critical') return 'Critical Local Anomaly Detected';
        if (action === 'BLOCK') return 'Preemptive block based on combined risk score';
        if (action === 'MONITOR') return 'Active monitoring enabled for suspicious behavior';
        return 'Standard policy applied';
    }

    private calculatePriority(action: SecurityAction, d2: DetectionResult, d3: EnrichedIOC): number {
        const base = action === 'ISOLATE_HOST' ? 100 : action === 'BLOCK' ? 90 : 50;
        const bonus = Math.max(d2.anomaly_score, (d3.threat_score || 0)) * 0.1;
        return Math.min(100, base + bonus);
    }
}

export default DalionRottweiler;
