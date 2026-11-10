import { DetectionResult } from '../d2_sentinela/types';
import { EnrichedIOC } from '../d3_espionagem/types';
import { ClassificationResult, ThreatType } from '../d10_ethos/types';
import { StrategicDecision, SecurityAction, SDEConfig } from './types';
import { HostContext } from '../../core/orchestrator/DalionStateContext';

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
     * Added HostContext support for Phase 9 Trajectory Tracking
     */
    public decide(d2: DetectionResult, d3: EnrichedIOC, d10?: ClassificationResult, hostContext?: HostContext): StrategicDecision {
        const timestamp = new Date().toISOString();

        // 1. Determine action based on hierarchical signals + Context (AX-DLN-004)
        const action = this.arbitrateAction(d2, d3, d10, hostContext);

        // 2. Build decision object following StrategicDecision interface
        return {
            action,
            target: action === 'ISOLATE_HOST' ? d3.event?.source_ip : d3.ioc_value,
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

    private arbitrateAction(d2: DetectionResult, d3: EnrichedIOC, d10?: ClassificationResult, hostContext?: HostContext): SecurityAction {
        const localRisk = d2.anomaly_score;
        const globalRisk = d3.threat_score || 0;
        const threatType = d10?.threat_type || ThreatType.UNKNOWN;

        const psysec = d3.psysec;
        const isHighValueIntent = psysec?.profile?.intent === 'ESPIONAGE' || psysec?.profile?.skill_level === 'ELITE' || psysec?.profile?.skill_level === 'ADVANCED';
        if ((d3.event?.action === 'suricata_alert' && d3.event?.severity === 'critical') ||
            threatType === ThreatType.RANSOMWARE || (d2.tags || []).includes('shadow_copy_deletion') || isHighValueIntent) {
            return 'ISOLATE_HOST';
        }

        // PHASE 9: TRAJECTORY TRACKING (AX-DLN-004)
        // Se o host tem um histórico crescente de risco em eventos recentes, escalamos a ação.
        // Consideramos os 2 últimos scores + o score global atual como uma janela de 3.
        if (hostContext && hostContext.risk_score_trend.length >= 2) {
            const history = hostContext.risk_score_trend.slice(-2);
            const trend = [...history, globalRisk];
            const isEscalating = trend.every((v, i, a) => i === 0 || v >= a[i - 1]) && trend[2] > trend[0];

            if (isEscalating && globalRisk > 60) {
                return 'BLOCK';
            }
        }
        if (d3.event?.action === 'suricata_alert' && d3.event?.severity === 'high') {
            const msg = (d3.event?.message || "").toLowerCase();
            // SCENARIO 13: Alertas de SCAN sem reputação maliciosa confirmada devem ser MONITORADOS, não BLOQUEADOS
            // SCENARIO 19: Se for BRUTEFORCE, deve BLOQUEAR mesmo sendo um scan
            if (msg.includes('scan') && !msg.includes('bruteforce') && globalRisk < 80) return 'MONITOR';

            // High severity Suricata alerts (e.g., RCE, C2) deserve immediate containment
            return 'BLOCK';
        }

        // HIGH CONFIDENCE THREATS: Phishing, C2, APT or high score malware
        if (threatType === ThreatType.PHISHING || threatType === ThreatType.C2 || threatType === ThreatType.APT) {
            return 'BLOCK';
        }

        const tags = Array.from(new Set([
            ...(d2.tags || []),
            ...(d3.tags || []),
            ...(d10?.tags || [])
        ].map(t => t.toLowerCase())));

        const hasStrongMalwareSignal =
            tags.includes("suspicious_download_exe") ||
            tags.includes("binary_download_octet_stream") ||
            globalRisk >= 80;

        if (threatType === ThreatType.MALWARE && tags.includes("browser_to_shell") && !hasStrongMalwareSignal) {
            // Behavioral alert without external confirmation
            return 'MONITOR';
        }

        if (threatType === ThreatType.MALWARE && (tags.includes("binary_download_octet_stream") || tags.includes("suspicious_download_exe"))) {
            // Aggressive quarantine for malware downloads
            return 'QUARANTINE';
        }

        const highConfidenceMalware = threatType === ThreatType.MALWARE && (d10?.confidence || 0) >= 0.8;
        const hasBehavioralTag = tags.includes('suspicious_download_exe') || tags.includes('browser_to_shell') || tags.includes('registry_persistence');
        const isRealTarget = !d3.ioc_value.startsWith('event:');

        if (highConfidenceMalware && hasBehavioralTag && isRealTarget) {
            return 'QUARANTINE';
        }

        if (threatType === ThreatType.MALWARE && (localRisk > 80 || globalRisk > 80)) {
            return 'BLOCK'; // Fallback to BLOCK for lower confidence malware
        }

        // SCENARIO 19 FIX: Block Brute Force attempts based on signature/message or Tags
        const signature = (d3.event?.message || "").toLowerCase();
        const hasBruteForceTag = tags.some(t => t.includes('bruteforce') || t.includes('ssh_scan'));

        if (hasBruteForceTag || signature.includes('bruteforce') || signature.includes('bmv') || signature.includes('ssh_scan')) {
            return 'BLOCK';
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

        // MEDIUM RISK (Scenario 18 Beaconing Score 65)
        if (localRisk >= 60 || globalRisk >= 60) {
            return 'MONITOR';
        }

        // CLEAN/LOW RISK
        if (threatType === ThreatType.CLEAN && localRisk < 20) {
            return 'ALLOW';
        }

        return this.config.default_action;
    }

    private generateReason(action: SecurityAction, d2: DetectionResult, d3: EnrichedIOC, d10?: ClassificationResult): string {
        if (d3.event?.action === 'suricata_alert' && (d3.event.severity === 'critical' || d3.event.severity === 'high')) {
            return `Suricata ${d3.event.severity.toUpperCase()} alert: ${d3.event.message}`;
        }
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
