"use strict";
/**
 * Dalion D7 PsySec - Attacker Intent & Psychological Profiling Agent
 *
 * Analyzes behavioral signals to profile the threat actor's intent and skill.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DalionPsySec = void 0;
const types_1 = require("../d10_ethos/types");
const types_2 = require("./types");
class DalionPsySec {
    /**
     * Analyze intent based on tactical signals
     */
    analyze(d2, d10) {
        const tags = [...(d2.tags || []), ...(d10.tags || [])];
        const threatType = d10.threat_type;
        const profile = this.inferProfile(threatType, tags, d2.anomaly_score);
        return {
            profile,
            confidence: 0.8, // Base confidence for behavioral inference
            reasoning: this.generateReasoning(profile, threatType),
            timestamp: new Date().toISOString()
        };
    }
    inferProfile(threat, tags, score) {
        // Base profile
        const profile = {
            intent: types_2.IntentType.UNKNOWN,
            skill_level: types_2.SkillLevel.BEGINNER,
            persistence_score: score / 100,
            focus: 'wide',
            tags: []
        };
        // Rule 1: Ransomware + High Rate -> Financial Gain (Organized Crime)
        if (threat === types_1.ThreatType.RANSOMWARE || tags.includes('ransomware_behavior')) {
            profile.intent = types_2.IntentType.FINANCIAL_GAIN;
            profile.skill_level = types_2.SkillLevel.INTERMEDIATE;
            profile.focus = 'targeted';
            profile.tags.push('monetary_impact');
        }
        // Rule 2: C2 Beacon + Stealth -> Espionage/Advanced
        if (threat === types_1.ThreatType.C2 && score < 80) {
            profile.intent = types_2.IntentType.ESPIONAGE;
            profile.skill_level = types_2.SkillLevel.ADVANCED;
            profile.focus = 'targeted';
            profile.tags.push('stealthy_beacon');
        }
        // Rule 3: Phishing + Generic Lure -> Script Kiddie
        if (threat === types_1.ThreatType.PHISHING && !tags.includes('targeted_campaign')) {
            profile.intent = types_2.IntentType.SCRIPT_KIDDIE;
            profile.skill_level = types_2.SkillLevel.BEGINNER;
            profile.focus = 'wide';
        }
        // Rule 4: Registry Persistence + Shell -> Disruption/Intermediate
        if (tags.includes('registry_persistence') && tags.includes('browser_to_shell')) {
            profile.intent = types_2.IntentType.DISRUPTION;
            profile.skill_level = types_2.SkillLevel.INTERMEDIATE;
            profile.focus = 'targeted';
        }
        return profile;
    }
    generateReasoning(profile, threat) {
        return `Behavioral pattern indicates ${profile.intent} intent with ${profile.skill_level} skill level. Focus appears to be ${profile.focus}.`;
    }
}
exports.DalionPsySec = DalionPsySec;
exports.default = DalionPsySec;
