/**
 * Type definitions for Dalion D7 PsySec
 * Attacker Intent & Psychological Profiling Agent
 */

import { ThreatType } from '../d10_ethos/types';

export enum IntentType {
    ESPIONAGE = 'ESPIONAGE',
    SABOTAGE = 'SABOTAGE',
    FINANCIAL_GAIN = 'FINANCIAL_GAIN',
    DISRUPTION = 'DISRUPTION',
    SCRIPT_KIDDIE = 'SCRIPT_KIDDIE',
    UNKNOWN = 'UNKNOWN'
}

export enum SkillLevel {
    BEGINNER = 'BEGINNER',
    INTERMEDIATE = 'INTERMEDIATE',
    ADVANCED = 'ADVANCED',
    ELITE = 'ELITE'
}

export interface AttackerProfile {
    intent: IntentType;
    skill_level: SkillLevel;
    potential_origin?: string;
    persistence_score: number; // 0-1 (How persistent the attacker is)
    focus: 'wide' | 'targeted';
    tags: string[];
}

export interface PsySecAnalysis {
    profile: AttackerProfile;
    confidence: number;
    reasoning: string;
    timestamp: string;
}
