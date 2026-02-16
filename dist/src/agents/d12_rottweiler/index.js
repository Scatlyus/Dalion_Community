"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DalionRottweiler = void 0;
const types_1 = require("../d10_ethos/types");
class DalionRottweiler {
    config;
    constructor(config) {
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
    decide(d2, d3, d10) {
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
    arbitrateAction(d2, d3, d10) {
        const localRisk = d2.anomaly_score;
        const globalRisk = d3.threat_score || 0;
        const threatType = d10?.threat_type || types_1.ThreatType.UNKNOWN;
        const psysec = d3.psysec;
        // EMERGENCY: Ransomware, Espionage, or Elite Attacker
        const isHighValueIntent = psysec?.profile?.intent === 'ESPIONAGE' || psysec?.profile?.skill_level === 'ELITE' || psysec?.profile?.skill_level === 'ADVANCED';
        if (threatType === types_1.ThreatType.RANSOMWARE || (d2.tags || []).includes('shadow_copy_deletion') || isHighValueIntent) {
            return 'ISOLATE_HOST';
        }
        // HIGH CONFIDENCE THREATS: Phishing, C2, APT or high score malware
        if (threatType === types_1.ThreatType.PHISHING || threatType === types_1.ThreatType.C2 || threatType === types_1.ThreatType.APT) {
            return 'BLOCK';
        }
        const tags = [...(d2.tags || []), ...(d3.tags || [])];
        const highConfidenceMalware = threatType === types_1.ThreatType.MALWARE && (d10?.confidence || 0) >= 0.8;
        const hasBehavioralTag = tags.includes('suspicious_download_exe') || tags.includes('browser_to_shell') || tags.includes('registry_persistence');
        const isRealTarget = !d3.ioc_value.startsWith('event:');
        if (highConfidenceMalware && hasBehavioralTag && isRealTarget) {
            return 'QUARANTINE';
        }
        if (threatType === types_1.ThreatType.MALWARE && (localRisk > 80 || globalRisk > 80)) {
            return 'BLOCK'; // Fallback to BLOCK for lower confidence malware
        }
        // HEURISTIC OVERRIDE: If D10 is silent but D2 is critical
        if (d2.risk_level === 'critical' && d2.anomaly) {
            return 'BLOCK';
        }
        // MIXED RISK: High risk but not definitively malicious
        if (localRisk > 70 || globalRisk > 70) {
            if (d2.anomaly)
                return 'BLOCK'; // Preemptive block
            return 'MONITOR';
        }
        // CLEAN/LOW RISK
        if (threatType === types_1.ThreatType.CLEAN && localRisk < 20) {
            return 'ALLOW';
        }
        return this.config.default_action;
    }
    generateReason(action, d2, d3, d10) {
        if (d10 && d10.threat_type !== types_1.ThreatType.UNKNOWN && d10.threat_type !== types_1.ThreatType.CLEAN) {
            return `Taxonomic Override: ${d10.threat_type.toUpperCase()} confirmed by Ethos`;
        }
        if (d2.risk_level === 'critical')
            return 'Critical Local Anomaly Detected';
        if (action === 'BLOCK')
            return 'Preemptive block based on combined risk score';
        if (action === 'MONITOR')
            return 'Active monitoring enabled for suspicious behavior';
        return 'Standard policy applied';
    }
    calculatePriority(action, d2, d3) {
        const base = action === 'ISOLATE_HOST' ? 100 : action === 'BLOCK' ? 90 : 50;
        const bonus = Math.max(d2.anomaly_score, (d3.threat_score || 0)) * 0.1;
        return Math.min(100, base + bonus);
    }
}
exports.DalionRottweiler = DalionRottweiler;
exports.default = DalionRottweiler;
