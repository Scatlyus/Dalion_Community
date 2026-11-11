/**
 * KC7 Module 2: Enrichment & Pivoting Dataset Generator
 *
 * Simulates a multi-stage attack scenario:
 * - Stage 1: Initial compromise (malware callback)
 * - Stage 2: Lateral movement via SMB
 * - Stage 3: Data exfiltration via DNS tunneling
 * - Stage 4: C2 beaconing (periodic HTTPS callbacks)
 */

import * as fs from 'fs';
import * as path from 'path';

interface SuricataEvent {
    timestamp: string;
    event_type: string;
    src_ip: string;
    dest_ip: string;
    src_port?: number;
    dest_port?: number;
    proto?: string;
    alert?: {
        action: string;
        signature: string;
        signature_id: number;
        severity: number;
    };
    dns?: {
        query: string;
        qtype: string;
    };
    http?: {
        hostname: string;
        url: string;
        http_method: string;
        http_user_agent: string;
    };
    flow?: {
        bytes_toserver: number;
        bytes_toclient: number;
        pkts_toserver: number;
        pkts_toclient: number;
    };
}

// Known malicious IOCs for KC7 Module 2
const MALICIOUS_IOCS = {
    c2_server: '185.220.101.42',  // Known C2 infrastructure
    exfil_domain: 'data-exfil-tunnel.badactor.ru',
    lateral_target: '10.0.5.100',
    compromised_host: '10.0.1.50'
};

const BENIGN_TRAFFIC = [
    { ip: '8.8.8.8', domain: 'google.com' },
    { ip: '1.1.1.1', domain: 'cloudflare.com' },
    { ip: '142.250.185.46', domain: 'youtube.com' }
];

function generateTimestamp(baseTime: number, offsetMs: number): string {
    return new Date(baseTime + offsetMs).toISOString();
}

function generateKC7Dataset(): SuricataEvent[] {
    const events: SuricataEvent[] = [];
    const baseTime = Date.now() - 3600000; // 1 hour ago

    // === PHASE 1: Initial Compromise (Malware Callback) ===
    events.push({
        timestamp: generateTimestamp(baseTime, 0),
        event_type: 'alert',
        src_ip: MALICIOUS_IOCS.compromised_host,
        dest_ip: MALICIOUS_IOCS.c2_server,
        dest_port: 443,
        proto: 'TCP',
        alert: {
            action: 'allowed',
            signature: 'ET MALWARE Suspicious Outbound Connection to Known C2',
            signature_id: 2024001,
            severity: 1
        },
        http: {
            hostname: 'update-service.onion.to',
            url: '/api/v1/beacon',
            http_method: 'POST',
            http_user_agent: 'Mozilla/5.0 (Compat; MSIE 9.0)'
        },
        flow: {
            bytes_toserver: 256,
            bytes_toclient: 128,
            pkts_toserver: 3,
            pkts_toclient: 2
        }
    });

    // === PHASE 2: Lateral Movement (SMB Scanning) ===
    for (let i = 1; i <= 20; i++) {
        events.push({
            timestamp: generateTimestamp(baseTime, 60000 + i * 500),
            event_type: 'flow',
            src_ip: MALICIOUS_IOCS.compromised_host,
            dest_ip: `10.0.5.${100 + i}`,
            dest_port: 445,
            proto: 'TCP',
            flow: {
                bytes_toserver: 180,
                bytes_toclient: 0,
                pkts_toserver: 2,
                pkts_toclient: 0
            }
        });
    }

    // === PHASE 3: DNS Exfiltration (Tunneling Pattern) ===
    const exfilData = ['usr_db', 'passwd', 'financials', 'secrets', 'keys'];
    exfilData.forEach((chunk, idx) => {
        events.push({
            timestamp: generateTimestamp(baseTime, 120000 + idx * 2000),
            event_type: 'dns',
            src_ip: MALICIOUS_IOCS.compromised_host,
            dest_ip: '8.8.8.8',
            dest_port: 53,
            proto: 'UDP',
            dns: {
                query: `${chunk}.${Buffer.from(chunk).toString('base64').substring(0, 8)}.${MALICIOUS_IOCS.exfil_domain}`,
                qtype: 'TXT'
            }
        });
    });

    // === PHASE 4: C2 Beaconing (Periodic Callbacks) ===
    for (let beacon = 0; beacon < 10; beacon++) {
        events.push({
            timestamp: generateTimestamp(baseTime, 180000 + beacon * 30000), // Every 30s
            event_type: 'http',
            src_ip: MALICIOUS_IOCS.compromised_host,
            dest_ip: MALICIOUS_IOCS.c2_server,
            dest_port: 443,
            proto: 'TCP',
            http: {
                hostname: 'cdn-update.normal-looking-domain.com',
                url: `/check?id=${Math.random().toString(36).substring(7)}`,
                http_method: 'GET',
                http_user_agent: 'curl/7.68.0'
            },
            flow: {
                bytes_toserver: 120,
                bytes_toclient: 85,
                pkts_toserver: 2,
                pkts_toclient: 1
            }
        });
    }

    // === BENIGN TRAFFIC (Noise) ===
    for (let i = 0; i < 50; i++) {
        const benign = BENIGN_TRAFFIC[i % BENIGN_TRAFFIC.length];
        events.push({
            timestamp: generateTimestamp(baseTime, Math.random() * 300000),
            event_type: 'http',
            src_ip: `10.1.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}`,
            dest_ip: benign.ip,
            dest_port: 443,
            proto: 'TCP',
            http: {
                hostname: benign.domain,
                url: '/',
                http_method: 'GET',
                http_user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
            }
        });
    }

    return events.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
}

// Generate and save dataset
const dataset = generateKC7Dataset();
const outputPath = process.argv[2] || path.join(__dirname, '../data/kc7_module2/kc7_dataset.generated.json');

fs.writeFileSync(outputPath, JSON.stringify(dataset, null, 2), { flag: 'wx' });

console.log(`✅ KC7 Module 2 Dataset Generated`);
console.log(`   Events: ${dataset.length}`);
console.log(`   Output: ${outputPath}`);
console.log(`\n📊 Attack Profile:`);
console.log(`   - Initial Compromise: 1 event`);
console.log(`   - Lateral Movement: 20 SMB scans`);
console.log(`   - DNS Exfiltration: 5 TXT queries`);
console.log(`   - C2 Beaconing: 10 periodic callbacks`);
console.log(`   - Benign Noise: 50 events`);
console.log(`\n🎯 Expected Detections:`);
console.log(`   - D2 Sentinela: Should flag C2 IP, DNS tunneling, SMB burst`);
console.log(`   - D3 Espionagem: Should enrich C2 IP with VirusTotal/AbuseIPDB data`);
console.log(`   - D12 Rottweiler: Should recommend ISOLATE or BLOCK`);
