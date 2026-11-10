/**
 * Dalion D7 PsySec - Attacker Intent & Psychological Profiling Agent
 * 
 * Analyzes behavioral signals to profile the threat actor's intent and skill.
 */

import { DetectionResult, SecurityEvent } from '../d2_sentinela/types';
import { ClassificationResult, ThreatType } from '../d10_ethos/types';
import { PsySecAnalysis, IntentType, SkillLevel, AttackerProfile } from './types';

export class DalionPsySec {
    /**
     * Profile an actor based on a history of events
     */
    public profileActor(events: SecurityEvent[]): AttackerProfile {
        if (events.length === 0) {
            return {
                intent: IntentType.UNKNOWN,
                skill_level: SkillLevel.BEGINNER,
                persistence_score: 0,
                focus: 'wide',
                tags: ['no_history']
            };
        }

        const uniqueTargets = new Set(events.map(e => e.destination_ip).filter(Boolean));
        const failCount = events.filter(e => e.status === 'failure' || e.status === 'blocked').length;
        const totalEvents = events.length;

        // Cálculo de persistência: proporção de falhas e volume
        const persistence = Math.min(1.0, (failCount / totalEvents) + (totalEvents / 20));

        // Inferência de foco e skill
        const isTargeted = uniqueTargets.size > 0 && uniqueTargets.size <= 2 && totalEvents > 3;
        const skill = totalEvents > 10 ? SkillLevel.ADVANCED : totalEvents > 5 ? SkillLevel.INTERMEDIATE : SkillLevel.BEGINNER;

        return {
            intent: uniqueTargets.size === 0 ? IntentType.UNKNOWN : isTargeted ? IntentType.ESPIONAGE : IntentType.DISRUPTION,
            skill_level: skill,
            persistence_score: persistence,
            focus: isTargeted ? 'targeted' : 'wide',
            tags: totalEvents > 5 ? ['persistent_actor'] : ['exploratory_phase']
        };
    }

    /**
     * Analyze intent based on tactical signals
     */
    public analyze(d2: DetectionResult, d10: ClassificationResult): PsySecAnalysis {
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

    private inferProfile(threat: ThreatType, tags: string[], score: number): AttackerProfile {
        // Base profile
        const profile: AttackerProfile = {
            intent: IntentType.UNKNOWN,
            skill_level: SkillLevel.BEGINNER,
            persistence_score: score / 100,
            focus: 'wide',
            tags: []
        };

        // Rule 1: Ransomware + High Rate -> Financial Gain (Organized Crime)
        if (threat === ThreatType.RANSOMWARE || tags.includes('ransomware_behavior')) {
            profile.intent = IntentType.FINANCIAL_GAIN;
            profile.skill_level = SkillLevel.INTERMEDIATE;
            profile.focus = 'targeted';
            profile.tags.push('monetary_impact');
        }

        // Rule 2: C2 Beacon + Stealth -> Espionage/Advanced
        if (threat === ThreatType.C2 && score < 80) {
            profile.intent = IntentType.ESPIONAGE;
            profile.skill_level = SkillLevel.ADVANCED;
            profile.focus = 'targeted';
            profile.tags.push('stealthy_beacon');
        }

        // Rule 3: Phishing + Generic Lure -> Script Kiddie
        if (threat === ThreatType.PHISHING && !tags.includes('targeted_campaign')) {
            profile.intent = IntentType.SCRIPT_KIDDIE;
            profile.skill_level = SkillLevel.BEGINNER;
            profile.focus = 'wide';
        }

        // Rule 4: Registry Persistence + Shell -> Disruption/Intermediate
        if (tags.includes('registry_persistence') && tags.includes('browser_to_shell')) {
            profile.intent = IntentType.DISRUPTION;
            profile.skill_level = SkillLevel.INTERMEDIATE;
            profile.focus = 'targeted';
        }

        return profile;
    }

    private generateReasoning(profile: AttackerProfile, threat: ThreatType): string {
        return `Behavioral pattern indicates ${profile.intent} intent with ${profile.skill_level} skill level. Focus appears to be ${profile.focus}.`;
    }
}

export default DalionPsySec;
