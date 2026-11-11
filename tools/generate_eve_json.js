const fs = require('fs');

const scenarios = [
    {
        "_comment": "=== CENÁRIO 1: DNS LEGÍTIMO — Google DNS ===",
        "timestamp": "2026-02-13T08:00:01.000Z",
        "event_type": "dns",
        "src_ip": "192.168.1.10",
        "dest_ip": "8.8.8.8",
        "dns": { "query": [{ "rrname": "google.com", "rrtype": "A" }], "type": "query" },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    },
    {
        "_comment": "=== CENÁRIO 2: DNS LEGÍTIMO — Microsoft ===",
        "timestamp": "2026-02-13T08:00:05.000Z",
        "event_type": "dns",
        "src_ip": "192.168.1.11",
        "dest_ip": "8.8.8.8",
        "dns": { "query": [{ "rrname": "microsoft.com", "rrtype": "A" }], "type": "query" },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    },
    {
        "_comment": "=== CENÁRIO 3: DNS LEGÍTIMO — GitHub ===",
        "timestamp": "2026-02-13T08:00:10.000Z",
        "event_type": "dns",
        "src_ip": "192.168.1.12",
        "dest_ip": "1.1.1.1",
        "dns": { "query": [{ "rrname": "github.com", "rrtype": "A" }], "type": "query" },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    },
    {
        "_comment": "=== CENÁRIO 4: HTTP LEGÍTIMO — Update server ===",
        "timestamp": "2026-02-13T08:01:00.000Z",
        "event_type": "http",
        "src_ip": "192.168.1.10",
        "dest_ip": "13.107.42.14",
        "http": {
            "hostname": "update.microsoft.com",
            "url": "/updates/catalog/v7",
            "http_method": "GET",
            "http_content_type": "application/json",
            "status": 200
        },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    },
    {
        "_comment": "=== CENÁRIO 5: HTTP LEGÍTIMO — CDN comum ===",
        "timestamp": "2026-02-13T08:01:10.000Z",
        "event_type": "http",
        "src_ip": "192.168.1.15",
        "dest_ip": "104.18.32.68",
        "http": {
            "hostname": "cdnjs.cloudflare.com",
            "url": "/ajax/libs/jquery/3.6.0/jquery.min.js",
            "http_method": "GET",
            "http_content_type": "application/javascript",
            "status": 200
        },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    },
    {
        "_comment": "=== CENÁRIO 6: ALERTA CRÍTICO — IP C2 conhecido (TA0011) ===",
        "timestamp": "2026-02-13T08:02:00.000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.20",
        "dest_ip": "45.133.1.25",
        "alert": {
            "signature": "ET MALWARE CobaltStrike Beacon",
            "signature_id": 2019240,
            "category": "A Network Trojan was detected",
            "severity": 1
        },
        "_expected": { "d12_action": "BLOCK", "d10_type": "C2", "mitre": "TA0011" }
    },
    {
        "_comment": "=== CENÁRIO 7: ALERTA CRÍTICO — Ransomware lateral movement ===",
        "timestamp": "2026-02-13T08:02:15.000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.20",
        "dest_ip": "192.168.1.50",
        "alert": {
            "signature": "ET POLICY SMB Lateral Movement",
            "signature_id": 2025715,
            "category": "Ransomware Activity",
            "severity": 1
        },
        "_expected": { "d12_action": "ISOLATE_HOST", "d10_type": "Ransomware", "mitre": "TA0008" }
    },
    {
        "_comment": "=== CENÁRIO 8: ALERTA ALTO — Phishing via DNS ===",
        "timestamp": "2026-02-13T08:03:00.000Z",
        "event_type": "dns",
        "src_ip": "192.168.1.30",
        "dest_ip": "8.8.8.8",
        "dns": {
            "query": [{ "rrname": "microsoft-security-verify.tk", "rrtype": "A" }],
            "type": "query"
        },
        "alert": {
            "signature": "ET DNS Query for Suspicious TLD .tk",
            "signature_id": 2027865,
            "category": "Potentially Bad Traffic",
            "severity": 2
        },
        "_expected": { "d12_action": "BLOCK", "d10_type": "Phishing" }
    },
    {
        "_comment": "=== CENÁRIO 9: HTTP MALICIOSO — Download de .exe via octet-stream ===",
        "timestamp": "2026-02-13T08:04:00.000Z",
        "event_type": "http",
        "src_ip": "192.168.1.35",
        "dest_ip": "185.123.45.67",
        "http": {
            "hostname": "dl.malware-drop.ru",
            "url": "/payload/update.exe",
            "http_method": "GET",
            "http_content_type": "application/octet-stream",
            "status": 200
        },
        "alert": {
            "signature": "ET MALWARE Executable Download from Suspicious Host",
            "signature_id": 2021001,
            "category": "A Network Trojan was detected",
            "severity": 1
        },
        "_expected": { "d12_action": "QUARANTINE", "d10_type": "Malware" }
    },
    {
        "_comment": "=== CENÁRIO 10: HTTP MALICIOSO — C2 via HTTP beaconing ===",
        "timestamp": "2026-02-13T08:05:00.000Z",
        "event_type": "http",
        "src_ip": "192.168.1.40",
        "dest_ip": "91.92.109.43",
        "http": {
            "hostname": "91.92.109.43",
            "url": "/jquery.min.php?id=aGVsbG8=",
            "http_method": "GET",
            "http_content_type": "text/html",
            "status": 200
        },
        "alert": {
            "signature": "ET MALWARE HTTP C2 Beaconing Pattern",
            "signature_id": 2030500,
            "category": "A Network Trojan was detected",
            "severity": 1
        },
        "_expected": { "d12_action": "BLOCK", "d10_type": "C2" }
    },
    {
        "_comment": "=== CENÁRIO 11: DNS SUSPEITO — DGA domain pattern ===",
        "timestamp": "2026-02-13T08:06:00.000Z",
        "event_type": "dns",
        "src_ip": "192.168.1.45",
        "dest_ip": "8.8.8.8",
        "dns": { "query": [{ "rrname": "xk4jz9mq2rp.com", "rrtype": "A" }], "type": "query" },
        "_expected": { "d12_action": "BLOCK", "d10_type": "C2", "_note": "DGA pattern - random string domain" }
    },
    {
        "_comment": "=== CENÁRIO 12: FLOW LEGÍTIMO — Tráfego HTTPS normal ===",
        "timestamp": "2026-02-13T08:07:00.000Z",
        "event_type": "flow",
        "src_ip": "192.168.1.10",
        "dest_ip": "140.82.121.4",
        "flow": {
            "pkts_toserver": 12,
            "pkts_toclient": 18,
            "bytes_toserver": 1024,
            "bytes_toclient": 8192,
            "state": "established",
            "reason": "timeout",
            "alerted": false
        },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    },
    {
        "_comment": "=== CENÁRIO 13: ALERTA MÉDIO — Port scan ===",
        "timestamp": "2026-02-13T08:08:00.000Z",
        "event_type": "alert",
        "src_ip": "203.0.113.99",
        "dest_ip": "192.168.1.1",
        "alert": {
            "signature": "ET SCAN Nmap TCP Stealth Scan",
            "signature_id": 2000537,
            "category": "Attempted Information Leak",
            "severity": 2
        },
        "_expected": { "d12_action": "MONITOR", "d10_type": "Reconnaissance" }
    },
    {
        "_comment": "=== CENÁRIO 14: HTTP SUSPEITO — Phishing lookalike ===",
        "timestamp": "2026-02-13T08:09:00.000Z",
        "event_type": "http",
        "src_ip": "192.168.1.50",
        "dest_ip": "198.51.100.50",
        "http": {
            "hostname": "paypa1-secure-login.com",
            "url": "/login/verify",
            "http_method": "POST",
            "http_content_type": "application/x-www-form-urlencoded",
            "status": 200
        },
        "_expected": { "d12_action": "BLOCK", "d10_type": "Phishing" }
    },
    {
        "_comment": "=== CENÁRIO 15: ALERTA CRÍTICO — APT exfiltration ===",
        "timestamp": "2026-02-13T08:10:00.000Z",
        "event_type": "alert",
        "src_ip": "192.168.1.60",
        "dest_ip": "193.163.125.138",
        "alert": {
            "signature": "ET TROJAN APT Data Exfiltration via DNS TXT",
            "signature_id": 2033891,
            "category": "Trojan Activity",
            "severity": 1
        },
        "_expected": { "d12_action": "BLOCK", "d10_type": "Espionage", "mitre": "TA0010" }
    },
    {
        "_comment": "=== CENÁRIO 16: DNS LEGÍTIMO — Interno corporativo ===",
        "timestamp": "2026-02-13T08:11:00.000Z",
        "event_type": "dns",
        "src_ip": "192.168.1.70",
        "dest_ip": "192.168.1.1",
        "dns": {
            "query": [{ "rrname": "intranet.empresa.local", "rrtype": "A" }],
            "type": "query"
        },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    },
    {
        "_comment": "=== CENÁRIO 17: HTTP MALICIOSO — Trojan dropper ===",
        "timestamp": "2026-02-13T08:12:00.000Z",
        "event_type": "http",
        "src_ip": "192.168.1.75",
        "dest_ip": "77.91.78.200",
        "http": {
            "hostname": "cdn-secure-files.top",
            "url": "/files/installer.exe",
            "http_method": "GET",
            "http_content_type": "application/octet-stream",
            "status": 200
        },
        "alert": {
            "signature": "ET MALWARE Win32/Trojan Dropper Download",
            "signature_id": 2024897,
            "category": "A Network Trojan was detected",
            "severity": 1
        },
        "_expected": { "d12_action": "QUARANTINE", "d10_type": "Malware" }
    },
    {
        "_comment": "=== CENÁRIO 18: FLOW SUSPEITO — Beaconing interval fixo ===",
        "timestamp": "2026-02-13T08:13:00.000Z",
        "event_type": "flow",
        "src_ip": "192.168.1.80",
        "dest_ip": "45.155.204.15",
        "flow": {
            "pkts_toserver": 1,
            "pkts_toclient": 1,
            "bytes_toserver": 256,
            "bytes_toclient": 128,
            "state": "established",
            "reason": "timeout",
            "alerted": false
        },
        "_expected": { "d12_action": "MONITOR", "d10_type": "C2", "_note": "Pequeno payload fixo - padrão beaconing" }
    },
    {
        "_comment": "=== CENÁRIO 19: ALERTA ALTO — Brute force SSH ===",
        "timestamp": "2026-02-13T08:14:00.000Z",
        "event_type": "alert",
        "src_ip": "185.220.101.50",
        "dest_ip": "192.168.1.1",
        "alert": {
            "signature": "ET SCAN SSH BruteForce Login Attempt",
            "signature_id": 2001219,
            "category": "Attempted Administrator Privilege Gain",
            "severity": 2
        },
        "_expected": { "d12_action": "BLOCK", "d10_type": "BruteForce" }
    },
    {
        "_comment": "=== CENÁRIO 20: DNS LEGÍTIMO — NPM registry (dev environment) ===",
        "timestamp": "2026-02-13T08:15:00.000Z",
        "event_type": "dns",
        "src_ip": "192.168.1.90",
        "dest_ip": "1.1.1.1",
        "dns": {
            "query": [{ "rrname": "registry.npmjs.org", "rrtype": "A" }],
            "type": "query"
        },
        "_expected": { "d12_action": "ALLOW", "d10_type": null }
    }
];

const content = scenarios.map(s => {
    // Remove potential non-ascii in _comment just in case, or replace it
    if (s._comment) {
        s._comment = s._comment.replace(/CENÁRIO/g, 'SCENARIO').replace(/—/g, '-').replace(/Legítimo/ig, 'Legitimo');
    }
    return JSON.stringify(s);
}).join('\n');
const outputPath = process.argv[2] || 'tools/sample_eve.generated.json';
fs.writeFileSync(outputPath, content, { encoding: 'utf8', flag: 'wx' });
console.log(`Generated ${outputPath} with ${scenarios.length} events in strict JSONL format.`);
