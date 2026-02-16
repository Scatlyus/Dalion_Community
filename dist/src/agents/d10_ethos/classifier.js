"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ThreatClassifier = void 0;
const types_1 = require("./types");
class ThreatClassifier {
    rules = [];
    constructor() {
        this.initializeRules();
    }
    initializeRules() {
        // 1. Generic Malware Rule (Baseline/Fallback)
        this.rules.push({
            name: 'generic_malware_pattern',
            description: 'High threat score with no specific category',
            check: (enriched) => (enriched.threat_score || 0) >= 80,
            result: {
                threat_type: types_1.ThreatType.MALWARE,
                mitre_tactics: ['TA0002'], // Execution
                severity: 'high',
                recommended_action: 'quarantine'
            }
        });
        // 2. Phishing Rule
        this.rules.push({
            name: 'phishing_pattern',
            description: 'IOC linked to phishing categories, DGA, or shortened URLs with keywords',
            check: (enriched) => {
                const vtCats = enriched.enrichment?.virustotal?.categories || [];
                const tags = enriched.tags || [];
                const context = enriched.context || {};
                const isShortenedPhish = tags.includes('shortened_url') && tags.includes('phishing_keywords');
                const isDGAPhish = tags.includes('dga_like_domain') && (enriched.source === 'DNS' || enriched.source === 'MAIL_GATEWAY');
                return (enriched.ioc_type === 'domain' && (vtCats.includes('phishing') || vtCats.includes('malicious'))) ||
                    tags.includes('embedded_pdf_phishing') ||
                    tags.includes('suspicious_process_spawn') ||
                    isShortenedPhish || isDGAPhish;
            },
            result: {
                threat_type: types_1.ThreatType.PHISHING,
                mitre_tactics: ['TA0001'], // Initial Access
                mitre_techniques: ['T1566'], // Phishing
                severity: 'high',
                recommended_action: 'block'
            }
        });
        // 3. Ransomware Rule
        this.rules.push({
            name: 'ransomware_pattern',
            description: 'IOC linked to ransomware activity or encryption behavior',
            check: (enriched) => {
                const vtCats = (enriched.enrichment?.virustotal?.categories || []).map(c => c.toLowerCase());
                const tags = enriched.tags || [];
                const ransomTerms = ['ransom', 'crypt', 'locky', 'wannacry', 'bitpaymer'];
                return ransomTerms.some(term => vtCats.some(cat => cat.includes(term))) ||
                    tags.includes('shadow_copy_deletion') ||
                    tags.includes('ransomware_behavior');
            },
            result: {
                threat_type: types_1.ThreatType.RANSOMWARE,
                mitre_tactics: ['TA0040'], // Impact
                mitre_techniques: ['T1486'], // Data Encrypted for Impact
                severity: 'critical',
                recommended_action: 'isolate_host'
            }
        });
        // 4. C2 Beacon Rule
        this.rules.push({
            name: 'c2_pattern',
            description: 'IOC exhibiting C2 beaconing, malicious CIDR, or identified as C2',
            check: (enriched) => {
                const tags = enriched.tags || [];
                const vtCats = enriched.enrichment?.virustotal?.categories || [];
                return tags.includes('c2_communication_pattern') ||
                    tags.includes('malicious_cidr_range') ||
                    tags.includes('fresh_threat_intel_feed') ||
                    tags.includes('known_malicious_ioc') ||
                    vtCats.includes('c2') || vtCats.includes('botnet');
            },
            result: {
                threat_type: types_1.ThreatType.C2,
                mitre_tactics: ['TA0011'], // Command and Control
                mitre_techniques: ['T1071'], // Application Layer Protocol
                severity: 'critical',
                recommended_action: 'block'
            }
        });
        // 5. Malware Rule (Refined)
        this.rules.push({
            name: 'malware_logic_pattern',
            description: 'IOC linked to binary drops or browser-to-shell patterns',
            check: (enriched) => {
                const tags = enriched.tags || [];
                const context = enriched.context || {};
                const isDangerousDownload = tags.includes('suspicious_download_exe') || tags.includes('binary_download_octet_stream');
                const isBrowserShell = tags.includes('browser_to_shell');
                const isPersistence = tags.includes('registry_persistence');
                return isDangerousDownload || isBrowserShell || isPersistence;
            },
            result: {
                threat_type: types_1.ThreatType.MALWARE,
                mitre_tactics: ['TA0002', 'TA0003'], // Execution, Persistence
                severity: 'high',
                recommended_action: 'quarantine'
            }
        });
        // 6. Tactical Intelligence Rule (D4)
        this.rules.push({
            name: 'tactical_intel_rule',
            description: 'Confirmed attribution or campaign activity from tactical feeds',
            check: (enriched) => {
                const signals = (enriched.tactical?.signals || []);
                return signals.some(s => s.severity === 'critical' || s.severity === 'high');
            },
            result: {
                // If the threat is already identified, keep the type (e.g., PHISHING) but boost severity
                threat_type: undefined,
                severity: 'critical',
                recommended_action: 'block'
            }
        });
    }
    async classify(enriched) {
        let finalResult = {
            threat_type: types_1.ThreatType.UNKNOWN,
            mitre_tactics: [],
            mitre_techniques: [],
            confidence: enriched.confidence,
            severity: 'low',
            recommended_action: 'monitor',
            tags: []
        };
        for (const rule of this.rules) {
            if (await rule.check(enriched)) {
                finalResult.threat_type = rule.result.threat_type || finalResult.threat_type;
                finalResult.severity = this.upgradeSeverity(finalResult.severity, rule.result.severity || 'low');
                finalResult.mitre_tactics = [...new Set([...finalResult.mitre_tactics, ...(rule.result.mitre_tactics || [])])];
                finalResult.mitre_techniques = [...new Set([...finalResult.mitre_techniques, ...(rule.result.mitre_techniques || [])])];
                if (rule.result.recommended_action)
                    finalResult.recommended_action = rule.result.recommended_action;
                finalResult.tags.push(rule.name);
            }
        }
        if (finalResult.threat_type === types_1.ThreatType.UNKNOWN && enriched.threat_score < 10) {
            finalResult.threat_type = types_1.ThreatType.CLEAN;
            finalResult.recommended_action = 'allow';
        }
        return finalResult;
    }
    upgradeSeverity(current, target) {
        const levels = ['low', 'medium', 'high', 'critical'];
        return levels.indexOf(target) > levels.indexOf(current) ? target : current;
    }
}
exports.ThreatClassifier = ThreatClassifier;
