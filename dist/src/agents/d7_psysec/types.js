"use strict";
/**
 * Type definitions for Dalion D7 PsySec
 * Attacker Intent & Psychological Profiling Agent
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SkillLevel = exports.IntentType = void 0;
var IntentType;
(function (IntentType) {
    IntentType["ESPIONAGE"] = "ESPIONAGE";
    IntentType["SABOTAGE"] = "SABOTAGE";
    IntentType["FINANCIAL_GAIN"] = "FINANCIAL_GAIN";
    IntentType["DISRUPTION"] = "DISRUPTION";
    IntentType["SCRIPT_KIDDIE"] = "SCRIPT_KIDDIE";
    IntentType["UNKNOWN"] = "UNKNOWN";
})(IntentType || (exports.IntentType = IntentType = {}));
var SkillLevel;
(function (SkillLevel) {
    SkillLevel["BEGINNER"] = "BEGINNER";
    SkillLevel["INTERMEDIATE"] = "INTERMEDIATE";
    SkillLevel["ADVANCED"] = "ADVANCED";
    SkillLevel["ELITE"] = "ELITE";
})(SkillLevel || (exports.SkillLevel = SkillLevel = {}));
