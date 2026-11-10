import { DetectionRule, SecurityEvent } from '../types';

/**
 * Authentication-related detection rules
 */
export function getAuthenticationRules(): Map<string, DetectionRule> {
    const rules = new Map<string, DetectionRule>();

    // Rule 1: Failed Login Burst
    rules.set('failed_logins_burst', {
        name: 'failed_logins_burst',
        description: 'Multiple login failures in short period',
        impact_score: 70,
        check: async (event, history) => {
            if (event.action !== 'login' || event.status !== 'failure') return false;
            const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
            const recentEvents = history.get(event.source_ip) || [];
            const failedLogins = recentEvents.filter(e =>
                e.action === 'login' && e.status === 'failure' && e.timestamp >= fiveMinutesAgo
            );
            return failedLogins.length >= 3;
        }
    });

    // Rule 2: Suspicious Geo Login
    rules.set('suspicious_geo_login', {
        name: 'suspicious_geo_login',
        description: 'Login from unusual geographic location or device',
        impact_score: 85,
        check: async (event) => {
            if (event.action !== 'login' || !event.user_agent) return false;
            const suspiciousPatterns = [/curl/i, /wget/i, /python/i, /scanner/i, /bot/i];
            return suspiciousPatterns.some(pattern => pattern.test(event.user_agent!));
        }
    });

    // Rule 7: Behavioral Deviation
    rules.set('behavioral_deviation', {
        name: 'behavioral_deviation',
        description: 'Deviation from baseline behavior',
        impact_score: 75,
        check: async (event) => {
            const hour = new Date(event.timestamp).getHours();
            const isOddHour = hour < 6 || hour > 22;
            return isOddHour && event.action === 'login';
        }
    });

    // Rule 4: Unauthorized Access Attempt
    rules.set('unauthorized_access_attempt', {
        name: 'unauthorized_access_attempt',
        description: 'Attempt to access unauthorized resources',
        impact_score: 80,
        check: async (event) => event.status === 'blocked' && event.severity === 'high'
    });

    return rules;
}
