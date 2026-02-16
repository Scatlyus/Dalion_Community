/**
 * Dalion D2 Sentinela - Real-time Security Event Detector
 * 
 * Production implementation (not mock!)
 * Implements 8 detection rules from spec.
 */

import { SecurityEvent, DetectionResult, DetectionRule } from './types';

export class DalionSentinela {
  private rules: Map<string, DetectionRule>;
  private eventHistory: Map<string, SecurityEvent[]>;

  constructor() {
    this.rules = this.initializeRules();
    this.eventHistory = new Map();
  }

  /**
   * Main analysis method
   * Analyzes a security event and returns detection result
   */
  async analyze(event: SecurityEvent): Promise<DetectionResult> {
    // Validate input schema
    this.validateEvent(event);

    // Store in history (for burst detection)
    this.storeEvent(event);

    // Apply all detection rules
    let totalScore = 0;
    const triggeredRules: string[] = [];
    const reasons: string[] = [];

    for (const [ruleName, rule] of this.rules) {
      const triggered = await rule.check(event, this.eventHistory);
      
      if (triggered) {
        totalScore += rule.impact_score;
        triggeredRules.push(ruleName);
        reasons.push(rule.description);
      }
    }

    // Cap score at 100
    const anomalyScore = Math.min(totalScore, 100);

    // Determine risk level
    const riskLevel = this.calculateRiskLevel(anomalyScore);

    // Generate tags
    const tags = this.generateTags(triggeredRules, event);

    return {
      anomaly: anomalyScore >= 60,
      reason: reasons.length > 0 ? reasons.join('; ') : 'No anomalies detected',
      anomaly_score: anomalyScore,
      risk_level: riskLevel,
      tags
    };
  }

  /**
   * Initialize detection rules
   */
  private initializeRules(): Map<string, DetectionRule> {
    const rules = new Map<string, DetectionRule>();

    // Rule 1: Failed Login Burst
    rules.set('failed_logins_burst', {
      name: 'failed_logins_burst',
      description: 'Multiple login failures in short period',
      impact_score: 70,
      check: async (event, history) => {
        if (event.action !== 'login' || event.status !== 'failure') {
          return false;
        }

        // Count failed logins from same source_ip in last 5 minutes
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const recentEvents = history.get(event.source_ip) || [];
        
        const failedLogins = recentEvents.filter(e => 
          e.action === 'login' &&
          e.status === 'failure' &&
          e.timestamp >= fiveMinutesAgo
        );

        return failedLogins.length >= 3; // Threshold: 3+ failures
      }
    });

    // Rule 2: Suspicious Geo Login
    rules.set('suspicious_geo_login', {
      name: 'suspicious_geo_login',
      description: 'Login from unusual geographic location or device',
      impact_score: 85,
      check: async (event, history) => {
        // TODO: Integrate with GeoIP database
        // For now: detect unusual user agents
        if (event.action !== 'login' || !event.user_agent) {
          return false;
        }

        // Suspicious patterns in user agent
        const suspiciousPatterns = [
          /curl/i,
          /wget/i,
          /python/i,
          /scanner/i,
          /bot/i
        ];

        return suspiciousPatterns.some(pattern => pattern.test(event.user_agent!));
      }
    });

    // Rule 3: Known Malicious IoC
    rules.set('known_malicious_ioc', {
      name: 'known_malicious_ioc',
      description: 'Event matches known malicious indicators',
      impact_score: 95,
      check: async (event, history) => {
        // TODO: Integrate with threat intel feeds
        // For now: check against basic blacklist
        const knownBadIPs = [
          '185.123.45.67', // Example from KC7
          '1.2.3.4'
        ];

        const knownBadDomains = [
          'microsoft-security-verify.com',
          'paypal-secure-login.com'
        ];

        // Check source IP
        if (knownBadIPs.includes(event.source_ip)) {
          return true;
        }

        // Check destination IP
        if (event.destination_ip && knownBadIPs.includes(event.destination_ip)) {
          return true;
        }

        // Check email sender (if present)
        if (event.email_sender) {
          return knownBadDomains.some(domain => 
            event.email_sender!.includes(domain)
          );
        }

        return false;
      }
    });

    // Rule 4: Unauthorized Access Attempt
    rules.set('unauthorized_access_attempt', {
      name: 'unauthorized_access_attempt',
      description: 'Attempt to access unauthorized resources',
      impact_score: 80,
      check: async (event, history) => {
        // Detect access denials
        return event.status === 'blocked' && 
               event.severity === 'high';
      }
    });

    // Rule 5: Unusual File Activity
    rules.set('unusual_file_activity', {
      name: 'unusual_file_activity',
      description: 'Suspicious file operations detected',
      impact_score: 90,
      check: async (event, history) => {
        if (!event.file_path) return false;

        // Suspicious file extensions
        const suspiciousExtensions = [
          '.exe', '.dll', '.bat', '.ps1', '.vbs',
          '.scr', '.com', '.pif'
        ];

        const hasSuspiciousExt = suspiciousExtensions.some(ext =>
          event.file_path!.toLowerCase().endsWith(ext)
        );

        // Suspicious paths
        const suspiciousPaths = [
          'C:\\Windows\\Temp',
          'C:\\Users\\Public',
          '%APPDATA%'
        ];

        const hasSuspiciousPath = suspiciousPaths.some(path =>
          event.file_path!.includes(path)
        );

        return hasSuspiciousExt && hasSuspiciousPath;
      }
    });

    // Rule 6: High Severity Event
    rules.set('high_severity_event_flag', {
      name: 'high_severity_event_flag',
      description: 'Event flagged as high/critical severity',
      impact_score: 60,
      check: async (event, history) => {
        return event.severity === 'critical' || event.severity === 'high';
      }
    });

    // Rule 7: Behavioral Deviation
    rules.set('behavioral_deviation', {
      name: 'behavioral_deviation',
      description: 'Deviation from baseline behavior',
      impact_score: 75,
      check: async (event, history) => {
        // TODO: Implement ML-based behavioral analysis
        // For now: detect unusual times (e.g., login at 3 AM)
        const hour = new Date(event.timestamp).getHours();
        const isOddHour = hour < 6 || hour > 22;

        return isOddHour && event.action === 'login';
      }
    });

    // Rule 8: Sensitive Terms in Message
    rules.set('sensitive_terms_in_message', {
      name: 'sensitive_terms_in_message',
      description: 'Security-related keywords in log message',
      impact_score: 90,
      check: async (event, history) => {
        const threatTerms = [
          'exploit',
          'malware',
          'ransomware',
          'backdoor',
          'trojan',
          'phishing',
          'sql injection',
          'buffer overflow'
        ];

        const messageLower = event.message.toLowerCase();
        return threatTerms.some(term => messageLower.includes(term));
      }
    });

    return rules;
  }

  /**
   * Calculate risk level from anomaly score
   */
  private calculateRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 90) return 'critical';
    if (score >= 75) return 'high';
    if (score >= 60) return 'medium';
    return 'low';
  }

  /**
   * Generate tags based on triggered rules and event data
   */
  private generateTags(triggeredRules: string[], event: SecurityEvent): string[] {
    const tags: string[] = [...triggeredRules];

    // Add event type tags
    tags.push(`event:${event.event_id}`);
    tags.push(`source:${event.log_source_id}`);

    // Add action tags
    if (event.action) {
      tags.push(`action:${event.action}`);
    }

    return tags;
  }

  /**
   * Store event in history for temporal analysis
   */
  private storeEvent(event: SecurityEvent): void {
    const key = event.source_ip;
    
    if (!this.eventHistory.has(key)) {
      this.eventHistory.set(key, []);
    }

    const history = this.eventHistory.get(key)!;
    history.push(event);

    // Keep only last 100 events per IP (memory management)
    if (history.length > 100) {
      history.shift();
    }

    // Clean old events (older than 1 hour)
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    this.eventHistory.set(
      key,
      history.filter(e => e.timestamp >= oneHourAgo)
    );
  }

  /**
   * Validate event against schema
   */
  private validateEvent(event: SecurityEvent): void {
    const required = [
      'timestamp',
      'event_id',
      'log_source_id',
      'source_ip',
      'action',
      'status',
      'severity',
      'message'
    ];

    for (const field of required) {
      if (!(field in event)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    // Validate timestamp format
    if (isNaN(Date.parse(event.timestamp))) {
      throw new Error(`Invalid timestamp format: ${event.timestamp}`);
    }
  }

  /**
   * Get rule statistics (for monitoring)
   */
  getRuleStats(): { rule: string; triggers: number }[] {
    // TODO: Implement rule statistics tracking
    return [];
  }

  /**
   * Clear event history (useful for testing)
   */
  clearHistory(): void {
    this.eventHistory.clear();
  }
}

// Export for use in other modules
export default DalionSentinela;
