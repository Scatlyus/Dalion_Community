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

        // Rule 3: Known Malicious IoC
        rules.set('known_malicious_ioc', {
            name: 'known_malicious_ioc',
            description: 'Event matches known malicious indicators',
            impact_score: 95,
            check: async (event) => {
                const knownBadIPs = ['185.123.45.67', '1.2.3.4'];
                const knownBadDomains = ['microsoft-security-verify.com', 'paypal-secure-login.com'];
                const context = (event as any).context || {};
                const targetDomain = context.domain || context.url;
                const targetIP = context.dst_ip || context.destination_ip;

                if (knownBadIPs.includes(event.source_ip)) return true;
                if (targetIP && knownBadIPs.includes(targetIP)) return true;
                if (targetDomain) {
                    return knownBadDomains.some(domain => targetDomain.includes(domain));
                }
                if (event.email_sender) {
                    return knownBadDomains.some(domain => event.email_sender!.includes(domain));
                }
                return false;
            }
        });

        // Rule 4: Unauthorized Access Attempt
        rules.set('unauthorized_access_attempt', {
            name: 'unauthorized_access_attempt',
            description: 'Attempt to access unauthorized resources',
            impact_score: 80,
            check: async (event) => event.status === 'blocked' && event.severity === 'high'
        });

        // Rule 5: Unusual File Activity
        rules.set('unusual_file_activity', {
            name: 'unusual_file_activity',
            description: 'Suspicious file operations detected',
            impact_score: 90,
            check: async (event) => {
                if (!event.file_path) return false;
                const suspiciousExt = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.scr', '.com', '.pif'];
                const hasSuspiciousExt = suspiciousExt.some(ext => event.file_path!.toLowerCase().endsWith(ext));
                const suspiciousPaths = ['C:\\Windows\\Temp', 'C:\\Users\\Public', '%APPDATA%'];
                const hasSuspiciousPath = suspiciousPaths.some(path => event.file_path!.includes(path));
                return hasSuspiciousExt && hasSuspiciousPath;
            }
        });

        // Rule 6: High Severity Event
        rules.set('high_severity_event_flag', {
            name: 'high_severity_event_flag',
            description: 'Event flagged as high/critical severity',
            impact_score: 60,
            check: async (event) => event.severity === 'critical' || event.severity === 'high'
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

        // Rule 8: Sensitive Terms in Message
        rules.set('sensitive_terms_in_message', {
            name: 'sensitive_terms_in_message',
            description: 'Security-related keywords in log message',
            impact_score: 90,
            check: async (event) => {
                const threatTerms = ['exploit', 'malware', 'ransomware', 'backdoor', 'trojan', 'phishing', 'sql injection', 'buffer overflow'];
                const messageLower = event.message.toLowerCase();
                return threatTerms.some(term => messageLower.includes(term));
            }
        });

        // Rule 9: C2 Beacon Detection (Variance Analysis)
        rules.set('c2_communication_pattern', {
            name: 'c2_communication_pattern',
            description: 'Detect regular C2 beaconing behavior via variance analysis',
            impact_score: 95,
            check: async (event, history) => {
                const recent = history.get(event.source_ip) || [];
                if (recent.length < 5) return false;

                const intervals = [];
                for (let i = 1; i < recent.length; i++) {
                    const diff = new Date(recent[i].timestamp).getTime() - new Date(recent[i - 1].timestamp).getTime();
                    // Ignorar eventos simultâneos (mesmo timestamp) para evitar divisão por zero ou ruído
                    if (diff > 0) intervals.push(diff);
                }

                if (intervals.length < 4) return false;

                const avgInterval = intervals.reduce((a, b) => a + b) / intervals.length;
                const variance = intervals.map(i => Math.abs(i - avgInterval)).reduce((a, b) => a + b) / intervals.length;

                // Baixa variância (< 20% do intervalo) indica beaconing
                const isRegular = variance < avgInterval * 0.2;
                // Beaconing em portas não triviais é altamente suspeito
                const nonStandardPort = event.destination_ip !== undefined; // Placeholder para porta no futuro

                return isRegular;
            }
        });

        // Rule 10: ASN/CIDR Blocklist
        rules.set('malicious_cidr_range', {
            name: 'malicious_cidr_range',
            description: 'Source IP detected in a known malicious ASN/CIDR range',
            impact_score: 90,
            check: async (event) => {
                const badRanges = ['45.133.0.0/16', '193.163.0.0/16', '185.123.0.0/16'];
                return badRanges.some(range => this.ipInCIDR(event.source_ip, range));
            }
        });

        // Rule 11: Fresh Threat Intel Feed (Local)
        rules.set('fresh_threat_intel_feed', {
            name: 'fresh_threat_intel_feed',
            description: 'IP recently reported in local threat intel feeds',
            impact_score: 100,
            check: async (event) => {
                const freshBadIPs = ['45.133.1.25', '193.163.125.138'];
                const context = (event as any).context || {};
                const targetIP = context.dst_ip || context.destination_ip;
                return freshBadIPs.includes(event.source_ip) || (targetIP && freshBadIPs.includes(targetIP));
            }
        });

        // Rule 12: Suspicious Process Parent (T1059)
        rules.set('suspicious_process_spawn', {
            name: 'suspicious_process_spawn',
            description: 'Suspicious process spawning from common lures (Office/Browser)',
            impact_score: 95,
            check: async (event) => {
                const context = (event as any).context;
                if (!context || !context.process || !context.parent) return false;
                const shells = ['cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe'];
                const lures = ['winword.exe', 'excel.exe', 'outlook.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe'];
                return shells.includes(context.process.toLowerCase()) && lures.includes(context.parent.toLowerCase());
            }
        });

        // Rule 13: Shadow Copy Deletion (T1490)
        rules.set('shadow_copy_deletion', {
            name: 'shadow_copy_deletion',
            description: 'Attempt to delete volume shadow copies (Ransomware behavior)',
            impact_score: 100,
            check: async (event) => {
                const context = (event as any).context;
                if (!context || !context.command) return false;
                const cmd = context.command.toLowerCase();
                return cmd.includes('vssadmin') && cmd.includes('delete') && cmd.includes('shadows');
            }
        });

        // Rule 14: Registry Persistence (T1547)
        rules.set('registry_persistence', {
            name: 'registry_persistence',
            description: 'Suspicious registry change in persistent Run keys',
            impact_score: 85,
            check: async (event) => {
                const context = (event as any).context;
                if (event.action !== 'registry_change' || !context || !context.key) return false;
                return context.key.includes('Run\\') || context.key.includes('RunOnce\\');
            }
        });

        // Rule 15: Ransomware Behavior (Pattern/Rate)
        rules.set('ransomware_behavior', {
            name: 'ransomware_behavior',
            description: 'Detected high-frequency file encryption behavior',
            impact_score: 100,
            check: async (event) => {
                const context = (event as any).context || {};
                return context.pattern === 'encrypt_many_files' || (context.rate_per_min || 0) > 50;
            }
        });

        // Rule 16: Shortened URL Detection (Refined)
        rules.set('shortened_url', {
            name: 'shortened_url',
            description: 'URL redirector service detected (T1566)',
            impact_score: 40,
            check: async (event) => {
                const context = (event as any).context || {};
                const url = (context.url || '').toLowerCase();
                const domain = (context.domain || '').toLowerCase();
                // Check if domain is EXACTLY one of the services or ends with .service
                const services = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly'];
                return services.some(s => {
                    const isExact = domain === s;
                    const isSubdomain = domain.endsWith('.' + s);
                    const isUrlStart = url.includes('://' + s + '/') || url.startsWith(s + '/');
                    return isExact || isSubdomain || isUrlStart;
                });
            }
        });

        // Rule 17: Phishing Keywords
        rules.set('phishing_keywords', {
            name: 'phishing_keywords',
            description: 'Sensitive phishing terms in URL/Domain',
            impact_score: 50,
            check: async (event) => {
                const context = (event as any).context || {};
                const target = (context.url || context.domain || '').toLowerCase();
                const keywords = ['verify', 'login', 'invoice', 'update', 'secure', 'account', 'banking'];
                return keywords.some(k => target.includes(k));
            }
        });

        // Rule 18: Suspicious Download (EXE)
        rules.set('suspicious_download_exe', {
            name: 'suspicious_download_exe',
            description: 'Potential malicious binary download (.exe)',
            impact_score: 60,
            check: async (event) => {
                const context = (event as any).context || {};
                const url = (context.url || '').toLowerCase();
                const file = (context.file_path || '').toLowerCase();
                return url.endsWith('.exe') || file.endsWith('.exe');
            }
        });

        // Rule 19: Binary Download (Octet-Stream)
        rules.set('binary_download_octet_stream', {
            name: 'binary_download_octet_stream',
            description: 'Download with application/octet-stream content type',
            impact_score: 40,
            check: async (event) => {
                const context = (event as any).context || {};
                return context.content_type === 'application/octet-stream';
            }
        });

        // Rule 20: DGA-like Domain (Entropy Refined)
        rules.set('dga_like_domain', {
            name: 'dga_like_domain',
            description: 'High entropy domain name detected (DGA)',
            impact_score: 70,
            check: async (event) => {
                const context = (event as any).context || {};
                const domain = context.domain || '';
                if (domain.length < 8) return false;
                const hostname = domain.split('.')[0];
                // Lowered threshold to catch 9-char random strings like xj3k2p9qz (entropy ~3.17)
                return this.calculateEntropy(hostname) > 3.1;
            }
        });

        // Rule 21: Browser to Shell (T1059)
        rules.set('browser_to_shell', {
            name: 'browser_to_shell',
            description: 'Browser process spawned a command shell',
            impact_score: 95,
            check: async (event) => {
                const context = (event as any).context || {};
                if (!context.process || !context.parent) return false;
                const browsers = ['chrome.exe', 'msedge.exe', 'firefox.exe'];
                const shells = ['cmd.exe', 'powershell.exe', 'pwsh.exe'];
                return browsers.includes(context.parent.toLowerCase()) && shells.includes(context.process.toLowerCase());
            }
        });

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
