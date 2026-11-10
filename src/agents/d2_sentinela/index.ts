/**
 * Dalion D2 Sentinela - Real-time Security Event Detector
 * 
 * Production implementation (not mock!)
 * Implements 8 detection rules from spec.
 */

import { SecurityEvent, DetectionResult, DetectionRule, IHistoryStore } from './types';
import { MemoryHistoryStore } from './MemoryHistoryStore';

export class DalionSentinela {
    public rules: Map<string, DetectionRule>;
    private historyStore: IHistoryStore;

    constructor(historyStore?: IHistoryStore) {
        this.rules = this.initializeRules();
        this.historyStore = historyStore || new MemoryHistoryStore();
    }

    /**
     * Main analysis method
     */
    async analyze(event: SecurityEvent): Promise<DetectionResult> {
        this.validateEvent(event);

        // Store in history (default cap 100)
        await this.historyStore.push(event.source_ip, event);

        // Fetch history for rules analysis
        const recentEvents = await this.historyStore.get(event.source_ip);
        const historySnapshot = new Map<string, SecurityEvent[]>();
        historySnapshot.set(event.source_ip, recentEvents);

        let totalScore = 0;
        const triggeredRules: string[] = [];
        const reasons: string[] = [];
        let rulesProcessed = 0;

        for (const [ruleName, rule] of this.rules) {
            rulesProcessed++;
            const triggered = await rule.check(event, historySnapshot);

            if (triggered) {
                totalScore += rule.impact_score;
                triggeredRules.push(ruleName);
                reasons.push(rule.description);
            }
        }

        const anomalyScore = Math.min(totalScore, 100);
        const riskLevel = this.calculateRiskLevel(anomalyScore);
        const tags = this.generateTags(triggeredRules, event);

        return {
            anomaly: anomalyScore >= 60,
            reason: reasons.length > 0 ? reasons.join('; ') : 'No anomalies detected',
            anomaly_score: anomalyScore,
            risk_level: riskLevel,
            tags,
            rules_processed: rulesProcessed
        };
    }

    private initializeRules(): Map<string, DetectionRule> {
        const rules = new Map<string, DetectionRule>();

        // Import rules from modular rule files
        const { getAuthenticationRules } = require('./rules/authentication_rules');
        const { getMalwareRules } = require('./rules/malware_rules');
        const { getNetworkRules } = require('./rules/network_rules');
        const { getAttackTechniqueRules } = require('./rules/attack_technique_rules');
        const { getPhishingRules } = require('./rules/phishing_rules');

        // Merge all rule sets
        const ruleSets = [
            getAuthenticationRules(),
            getMalwareRules(),
            getNetworkRules(),
            getAttackTechniqueRules(),
            getPhishingRules()
        ];

        for (const ruleSet of ruleSets) {
            for (const [key, rule] of ruleSet) {
                rules.set(key, rule);
            }
        }

        return rules;
    }

    public calculateEntropy(str: string): number {
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

    /**
     * Helper to check if IP is in CIDR range (IPv4 only)
     */
    private ipInCIDR(ip: string, cidr: string): boolean {
        try {
            const [range, bits] = cidr.split('/');
            const mask = ~(Math.pow(2, 32 - parseInt(bits)) - 1);

            const ipToNum = (addr: string) => addr.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;

            return (ipToNum(ip) & mask) === (ipToNum(range) & mask);
        } catch {
            return false;
        }
    }

    private calculateRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
        if (score >= 90) return 'critical';
        if (score >= 75) return 'high';
        if (score >= 60) return 'medium';
        return 'low';
    }

    private generateTags(triggeredRules: string[], event: SecurityEvent): string[] {
        const tags: string[] = [...triggeredRules, `event:${event.event_id}`, `source:${event.log_source_id}`];
        if (event.action) tags.push(`action:${event.action}`);
        return tags;
    }

    private validateEvent(event: SecurityEvent): void {
        const required = ['timestamp', 'event_id', 'log_source_id', 'source_ip', 'action', 'status', 'severity', 'message'];
        for (const field of required) {
            if (!(field in event)) throw new Error(`Missing required field: ${field}`);
        }
        if (isNaN(Date.parse(event.timestamp))) throw new Error(`Invalid timestamp format: ${event.timestamp}`);
    }

    async clearHistory(): Promise<void> {
        await this.historyStore.clear();
    }
}

export default DalionSentinela;
