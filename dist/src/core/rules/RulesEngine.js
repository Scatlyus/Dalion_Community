"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RulesEngine = void 0;
class RulesEngine {
    rules = [];
    constructor() {
        this.initializeDefaultRules();
    }
    initializeDefaultRules() {
        this.rules.push({
            id: 'RULE_001_SPOOF_DOMAIN',
            description: 'Detects domains trying to mimic official services',
            condition: (log) => {
                const patterns = ['microsoft-security', 'verify-auth', 'secure-login', 'verify-ms'];
                return log.sender ? patterns.some(p => log.sender.includes(p)) : false;
            },
            score: 0.85,
            anomaly_type: 'spoofing_attempt'
        });
        this.rules.push({
            id: 'RULE_002_SUSPICIOUS_TLD',
            description: 'Detects unusual TLDs in email senders',
            condition: (log) => {
                const suspiciousTlds = ['.net', '.xyz', '.info', '.top'];
                return log.sender ? suspiciousTlds.some(tld => log.sender.endsWith(tld)) : false;
            },
            score: 0.40,
            anomaly_type: 'high_risk_tld'
        });
        this.rules.push({
            id: 'RULE_003_EGRESS_ANOMALY',
            description: 'Detects large outbound data to non-standard ports',
            condition: (log) => {
                return (log.bytes_sent || 0) > 1000 && log.dest_port !== 443 && log.dest_port !== 80;
            },
            score: 0.70,
            anomaly_type: 'suspicious_egress'
        });
    }
    evaluate(log) {
        let totalScore = 0;
        const matches = [];
        for (const rule of this.rules) {
            if (rule.condition(log)) {
                matches.push(rule);
                totalScore = Math.max(totalScore, rule.score); // Usando max score por enquanto
            }
        }
        return {
            detected: matches.length > 0,
            matches,
            totalScore
        };
    }
}
exports.RulesEngine = RulesEngine;
