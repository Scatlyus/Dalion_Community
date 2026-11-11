/**
 * 🛰️ DALION STRESS TEST - Synthetic EVE Log Generator
 *
 * Generates realistic Suricata EVE JSON logs for performance testing.
 *
 * Distribution:
 * - 70% Legitimate Traffic (DNS, HTTP)
 * - 20% Benign Anomalies (Port scans, rate limiting)
 * - 10% Real Threats (Malware, Phishing, C2, Ransomware, Brute Force)
 */

import * as crypto from 'crypto';
import * as fs from 'fs';

interface GeneratorConfig {
    totalEvents: number;
    distribution: {
        legitimate: number;  // 0.7
        anomalies: number;   // 0.2
        threats: number;     // 0.1
    };
}

// Top legitimate domains (sampled from Alexa Top 1000)
const LEGITIMATE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'twitter.com', 'linkedin.com', 'instagram.com', 'reddit.com', 'netflix.com',
    'github.com', 'stackoverflow.com', 'wikipedia.org', 'cloudflare.com', 'apple.com',
    'adobe.com', 'zoom.us', 'dropbox.com', 'salesforce.com', 'slack.com'
];

const THREAT_SIGNATURES = {
    phishing: [
        'paypa1-secure-login.com',
        'g00gle-verify.tk',
        'microsoft-security-verify.tk',
        'amazon-account-suspended.ru',
        'facebook-security-alert.xyz'
    ],
    dga: [] as string[], // Will be generated dynamically
    malware: [
        'dl.malware-drop.ru',
        'cdn-secure-files.top',
        'update-installer.xyz'
    ],
    c2: [
        '45.133.1.25',
        '91.92.109.43',
        '193.163.125.138'
    ],
    ransomware: [
        'ET MALWARE Ransomware Lateral Movement Detected',
        'ET EXPLOIT Possible Ransomware Activity',
        'SURICATA FileInfo SHA256 match on ransomware'
    ],
    bruteforce: [
        'ET SCAN SSH Brute Force Attempt',
        'SURICATA SSH Excessive Password Authentication',
        'ET SCAN Potential SSH Scan'
    ]
};

// Generate DGA domain (random alphanumeric)
function generateDGA(): string {
    const length = 10 + Math.floor(Math.random() * 10);
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let domain = '';
    for (let i = 0; i < length; i++) {
        domain += chars[Math.floor(Math.random() * chars.length)];
    }
    return `${domain}.com`;
}

// Generate random IP
function randomIP(internal: boolean = false): string {
    if (internal) {
        return `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }
    return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

// Generate timestamp (last 24 hours)
function randomTimestamp(): string {
    const now = Date.now();
    const dayAgo = now - (24 * 60 * 60 * 1000);
    const randomTime = dayAgo + Math.random() * (24 * 60 * 60 * 1000);
    return new Date(randomTime).toISOString();
}

// EVENT GENERATORS

function generateLegitimateEvent(): any {
    const type = Math.random() < 0.5 ? 'dns' : 'http';
    const timestamp = randomTimestamp();
    const srcIP = randomIP(true);
    const eventId = crypto.randomBytes(6).toString('hex');

    if (type === 'dns') {
        return {
            timestamp,
            event_type: 'dns',
            src_ip: srcIP,
            dest_ip: '8.8.8.8',
            dns: {
                query: [{
                    rrname: LEGITIMATE_DOMAINS[Math.floor(Math.random() * LEGITIMATE_DOMAINS.length)],
                    rrtype: 'A'
                }]
            },
            flow_id: parseInt(eventId, 16),
            _expected: { d12_action: 'ALLOW' }
        };
    } else {
        return {
            timestamp,
            event_type: 'http',
            src_ip: srcIP,
            dest_ip: randomIP(false),
            http: {
                hostname: LEGITIMATE_DOMAINS[Math.floor(Math.random() * LEGITIMATE_DOMAINS.length)],
                url: '/api/v1/data',
                http_method: 'GET',
                http_content_type: 'application/json',
                status: 200
            },
            flow_id: parseInt(eventId, 16),
            _expected: { d12_action: 'ALLOW' }
        };
    }
}

function generateAnomalyEvent(): any {
    const timestamp = randomTimestamp();
    const srcIP = randomIP(false);
    const eventId = crypto.randomBytes(6).toString('hex');

    return {
        timestamp,
        event_type: 'alert',
        src_ip: srcIP,
        dest_ip: randomIP(true),
        alert: {
            signature: 'ET SCAN Potential Port Scan',
            signature_id: 2000419,
            category: 'Attempted Information Leak',
            severity: 2
        },
        flow_id: parseInt(eventId, 16),
        _expected: { d12_action: 'MONITOR' }
    };
}

function generateThreatEvent(): any {
    const types = ['phishing', 'dga', 'malware', 'ransomware', 'bruteforce'];
    const type = types[Math.floor(Math.random() * types.length)];
    const timestamp = randomTimestamp();
    const srcIP = randomIP(true);
    const eventId = crypto.randomBytes(6).toString('hex');

    switch (type) {
        case 'phishing':
            return {
                timestamp,
                event_type: 'http',
                src_ip: srcIP,
                dest_ip: randomIP(false),
                http: {
                    hostname: THREAT_SIGNATURES.phishing[Math.floor(Math.random() * THREAT_SIGNATURES.phishing.length)],
                    url: '/login.php',
                    http_method: 'POST',
                    http_content_type: 'text/html'
                },
                flow_id: parseInt(eventId, 16),
                _expected: { d12_action: 'BLOCK' }
            };

        case 'dga':
            return {
                timestamp,
                event_type: 'dns',
                src_ip: srcIP,
                dest_ip: '8.8.8.8',
                dns: {
                    query: [{
                        rrname: generateDGA(),
                        rrtype: 'A'
                    }]
                },
                flow_id: parseInt(eventId, 16),
                _expected: { d12_action: 'BLOCK' }
            };

        case 'malware':
            return {
                timestamp,
                event_type: 'http',
                src_ip: srcIP,
                dest_ip: randomIP(false),
                http: {
                    hostname: THREAT_SIGNATURES.malware[Math.floor(Math.random() * THREAT_SIGNATURES.malware.length)],
                    url: '/payload.exe',
                    http_method: 'GET',
                    http_content_type: 'application/octet-stream'
                },
                alert: {
                    signature: 'ET MALWARE Trojan Download Detected',
                    signature_id: 2024364,
                    category: 'A Network Trojan was detected',
                    severity: 1
                },
                flow_id: parseInt(eventId, 16),
                _expected: { d12_action: 'QUARANTINE' }
            };

        case 'ransomware':
            return {
                timestamp,
                event_type: 'alert',
                src_ip: srcIP,
                dest_ip: randomIP(true),
                alert: {
                    signature: THREAT_SIGNATURES.ransomware[Math.floor(Math.random() * THREAT_SIGNATURES.ransomware.length)],
                    signature_id: 2028000 + Math.floor(Math.random() * 100),
                    category: 'Ransomware Detected',
                    severity: 1
                },
                flow_id: parseInt(eventId, 16),
                _expected: { d12_action: 'ISOLATE_HOST' }
            };

        case 'bruteforce':
            return {
                timestamp,
                event_type: 'alert',
                src_ip: randomIP(false),
                dest_ip: randomIP(true),
                alert: {
                    signature: THREAT_SIGNATURES.bruteforce[Math.floor(Math.random() * THREAT_SIGNATURES.bruteforce.length)],
                    signature_id: 2001219,
                    category: 'Attempted Login',
                    severity: 2
                },
                flow_id: parseInt(eventId, 16),
                _expected: { d12_action: 'BLOCK' }
            };

        default:
            return generateLegitimateEvent();
    }
}

// MAIN GENERATOR
async function generateStressDataset(config: GeneratorConfig, outputFile: string) {
    const events: any[] = [];
    const { totalEvents, distribution } = config;

    const legitCount = Math.floor(totalEvents * distribution.legitimate);
    const anomalyCount = Math.floor(totalEvents * distribution.anomalies);
    const threatCount = totalEvents - legitCount - anomalyCount;

    console.log(`🛰️ Generating ${totalEvents} events...`);
    console.log(`   ✅ Legitimate: ${legitCount}`);
    console.log(`   ⚠️  Anomalies: ${anomalyCount}`);
    console.log(`   🔴 Threats: ${threatCount}\n`);

    // Generate events
    for (let i = 0; i < legitCount; i++) {
        events.push(generateLegitimateEvent());
    }
    for (let i = 0; i < anomalyCount; i++) {
        events.push(generateAnomalyEvent());
    }
    for (let i = 0; i < threatCount; i++) {
        events.push(generateThreatEvent());
    }

    // Shuffle to mix timestamps
    events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    // Write to JSONL
    const jsonl = events.map(e => JSON.stringify(e)).join('\n');
    fs.writeFileSync(outputFile, jsonl, { encoding: 'utf-8', flag: 'wx' });

    console.log(`✅ Dataset generated: ${outputFile}`);
    console.log(`📊 Total size: ${(Buffer.byteLength(jsonl) / 1024 / 1024).toFixed(2)} MB\n`);
}

// CLI Execution
const args = process.argv.slice(2);
const totalEvents = args[0] === undefined ? 100000 : Number(args[0]);
const outputFile = args[1] || 'tools/stress_dataset.json';

const config: GeneratorConfig = {
    totalEvents,
    distribution: {
        legitimate: 0.70,
        anomalies: 0.20,
        threats: 0.10
    }
};

if (!Number.isSafeInteger(totalEvents) || totalEvents <= 0) {
    console.error('Event count must be a positive integer.');
    process.exitCode = 1;
} else {
    generateStressDataset(config, outputFile).catch(error => { console.error(error); process.exitCode = 1; });
}
