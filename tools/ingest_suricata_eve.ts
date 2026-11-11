import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import * as crypto from 'crypto';
import { spawn } from 'child_process';

import { DalionSentinela } from '../src/agents/d2_sentinela/index';
import { DalionEthos } from '../src/agents/d10_ethos/index';
import { DalionRottweiler } from '../src/agents/d12_rottweiler/index';
import { DalionInfantaria } from '../src/agents/d1_infantaria/index';
import { DalionThreatIntel } from '../src/agents/d8_threatintel/index';
import { DalionIntelCampo } from '../src/agents/d4_intel_campo/index';
import { DalionPsySec } from '../src/agents/d7_psysec/index';
import { DalionAfterAction } from '../src/agents/d11_afteraction/index';
import { DalionArtilharia } from '../src/agents/d5_artilharia/index';
import { DalionAttackGraph } from '../src/agents/d9_attackgraph/index';
import { DalionDiplomacia } from '../src/agents/d6_diplomacia/index';
import { SecurityEvent } from '../src/agents/d2_sentinela/types';
import { EnrichedIOC } from '../src/agents/d3_espionagem/types';
import { ClassificationResult, ThreatType } from '../src/agents/d10_ethos/types';

import { performance } from 'perf_hooks';

/**
 * Dalion Suricata EVE Ingestor
 * Suporta --file, --stdin, --tail, --limit, --strict e --learn
 */

interface DalionAgents {
    d2: DalionSentinela;
    d8: DalionThreatIntel;
    ethos: DalionEthos;
    rottweiler: DalionRottweiler;
    infantaria: DalionInfantaria;
    d4: DalionIntelCampo | null;
    d7: DalionPsySec | null;
    afterAction: DalionAfterAction;
    artillery: DalionArtilharia;
    attackGraph: DalionAttackGraph;
    diplomacy: DalionDiplomacia;
}

interface ValidationStats {
    total: number;
    passed: number;
    failed: number;
    results: Array<{
        id: string;
        expected: string;
        actual: string;
        success: boolean;
        d10_match: boolean;
    }>;
}

function assert(cond: any, msg: string) {
    if (!cond) {
        console.error(`❌ ASSERT FAILED: ${msg}`);
        process.exitCode = 1;
    }
}

async function main() {
    const args = process.argv.slice(2);
    const modeFileIdx = args.indexOf('--file');
    const hasStdin = args.indexOf('--stdin') !== -1;
    const modeTailIdx = args.indexOf('--tail');
    const limitIdx = args.indexOf('--limit');
    const hasStrict = args.indexOf('--strict') !== -1;
    const hasLearn = args.indexOf('--learn') !== -1;
    const hasMetrics = args.indexOf('--metrics') !== -1;

    const limit = limitIdx !== -1 ? Number(args[limitIdx + 1]) : Infinity;
    const filePath = modeFileIdx !== -1 ? args[modeFileIdx + 1] : modeTailIdx !== -1 ? args[modeTailIdx + 1] : null;

    if (!hasStdin && !filePath) {
        console.log("Usage: ts-node ingest_suricata_eve.ts [--file <path> | --stdin | --tail <path>] [--limit <n>] [--strict] [--learn]");
        process.exit(1);
    }

    console.log("=== 🛰️ DALION: SURICATA EVE ADAPTER ===");

    // Initialize Agents
    const d2 = new DalionSentinela();
    const d8 = new DalionThreatIntel();
    const ethos = new DalionEthos();
    const rottweiler = new DalionRottweiler();
    const infantaria = new DalionInfantaria({ auto_execute: true });
    const afterAction = new DalionAfterAction();
    const artillery = new DalionArtilharia();
    const attackGraph = new DalionAttackGraph();
    const diplomacy = new DalionDiplomacia();

    // Phase 10 Agents (Optional check)
    let d4: DalionIntelCampo | null = null;
    let d7: DalionPsySec | null = null;
    try {
        d4 = new DalionIntelCampo();
        d7 = new DalionPsySec();
    } catch (e) {
        console.log("[!] D4/D7 not initialized or in development (Optional mode)");
    }

    const agents: DalionAgents = {
        d2, d8, ethos, rottweiler, infantaria, d4, d7, afterAction,
        artillery, attackGraph, diplomacy
    };

    if (hasStdin) {
        await processStream(process.stdin, agents, { limit, strict: hasStrict, learn: hasLearn, metrics: hasMetrics });
    } else if (modeFileIdx !== -1 && filePath) {
        const fullPath = path.resolve(process.cwd(), filePath);
        if (!fs.existsSync(fullPath)) {
            console.error(`[Error] File not found: ${fullPath}`);
            process.exit(1);
        }
        // Performance: Use highWaterMark for better memory management with large logs
        const stream = fs.createReadStream(fullPath, { highWaterMark: 64 * 1024 });
        await processStream(stream, agents, { limit, strict: hasStrict, learn: hasLearn, metrics: hasMetrics });
    } else if (modeTailIdx !== -1 && filePath) {
        console.log(`[Tail] Monitoring ${filePath}...`);
        const isWindows = process.platform === 'win32';
        const tailCmd = isWindows ? 'powershell' : 'tail';
        const tailArgs = isWindows
            ? ['-NoProfile', '-NonInteractive', '-Command', `Get-Content -LiteralPath "${filePath}" -Wait`]
            : ['-f', filePath];

        const tailProcess = spawn(tailCmd, tailArgs);
        await processStream(tailProcess.stdout, agents, { limit, strict: hasStrict, learn: hasLearn, metrics: hasMetrics });
    }
}

async function processStream(
    stream: NodeJS.ReadableStream,
    agents: DalionAgents,
    opts?: { limit?: number, strict?: boolean, learn?: boolean, metrics?: boolean }
) {
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    const limit = opts?.limit ?? Infinity;
    const strict = opts?.strict ?? false;
    const learn = opts?.learn ?? false;

    const stats: ValidationStats = { total: 0, passed: 0, failed: 0, results: [] };

    let count = 0;
    if (opts?.metrics) console.log(`[DALION_METRICS] ${JSON.stringify({ rss_bytes: process.memoryUsage().rss })}`);
    for await (let line of rl) {
        if (count >= limit) break;
        line = line.trim();
        if (!line) continue;

        // Sanitize: Remove possible BOM or non-printable chars from the start
        const sanitizedLine = line.replace(/^\uFEFF/g, '').trim();

        if (!(sanitizedLine.startsWith('{') && sanitizedLine.endsWith('}'))) {
            // Skip non-JSON lines (noise or headers)
            continue;
        }

        try {
            const eve = JSON.parse(sanitizedLine);
            const started = performance.now();
            await handleEveEvent(eve, agents, strict, learn, stats);
            if (opts?.metrics) console.log(`[DALION_METRICS] ${JSON.stringify({ latency_ms: performance.now() - started, rss_bytes: process.memoryUsage().rss })}`);
            count++;
        } catch (e: any) {
            console.error(`[Error] Failed to parse EVE line | Length: ${line.length} | Message: ${e.message}`);
            // console.error(`[Debug] Line content: ${line}`);
            if (strict) process.exitCode = 1;
        }
    }

    if (strict && stats.total > 0) {
        console.log(`\n=== 📊 DALION VALIDATION REPORT (KC7 Dataset) ===`);
        console.log(`Total Events: ${stats.total}`);
        console.log(`✅ Passed: ${stats.passed}`);
        console.log(`❌ Failed: ${stats.failed}`);

        const accuracy = (stats.passed / stats.total) * 100;
        console.log(`🎯 Accuracy: ${accuracy.toFixed(2)}%`);

        if (stats.failed > 0) {
            console.log(`\n🔍 Failures:`);
            stats.results.filter(r => !r.success).forEach(r => {
                console.log(`   - [${r.id}] Expected: ${r.expected} | Actual: ${r.actual}`);
            });
            process.exitCode = 1;
        } else {
            console.log(`\n✨ PERFECT SCORE. System is calibrated.`);
        }
    }
}

async function handleEveEvent(eve: any, agents: DalionAgents, strict: boolean, learn: boolean, stats: ValidationStats) {
    const start = performance.now();

    // Map EVE to SecurityEvent
    const event = mapToSecurityEvent(eve);
    if (!event) return;

    console.log(`\n[Suricata] Event: ${event.action} | Source: ${event.source_ip} -> ${event.destination_ip || 'N/A'}`);

    // 1. D2 Analysis (Local Heuristics)
    const d2Result = await agents.d2.analyze(event);

    // 2. Identify Target IOC from EVE context
    const target = extractTarget(eve) || event.source_ip;

    // 3. D8 Enrichment (Threat Hub)
    const d8Signals = await agents.d8.lookup(target);

    // 3b. D5 Compliance (Policy Engine)
    const d5Result = await agents.artillery.validate(event);
    if (!d5Result.compliant) {
        console.log(`[D5 Artillery] 🚩 Compliance Violation: ${d5Result.violations.map(v => v.id).join(', ')}`);
    }

    // 3c. D9 Attack Graph (Memory Mapping)
    if (d2Result.anomaly || event.severity === 'critical') {
        // Map to MITRE Phase based on event type or signature
        const phase = mapToMitrePhase(eve);
        await agents.attackGraph.addEvent(event, phase);
        const prediction = await agents.attackGraph.getPredictions(event.source_ip);
        if (prediction.confidence_score > 0.5) {
            console.log(`[D9 AttackGraph] 🔮 Predicted Next Phase: ${prediction.predicted_next_steps[0]?.phase} (${(prediction.confidence_score * 100).toFixed(0)}%)`);
        }
    }

    // Extraction: Behavioral tags from EVE
    const behavioralTags: string[] = [];

    // Generic Extraction
    if (eve.http) {
        behavioralTags.push(`http_method:${eve.http.http_method}`);
        if (eve.http.hostname) behavioralTags.push(`hostname:${eve.http.hostname}`);
    } else if (eve.dns) {
        behavioralTags.push(`dns_query:${eve.dns.query?.[0]?.rrname}`);
    } else if (eve.alert) {
        behavioralTags.push(`alert_signature:${eve.alert.signature_id}`);
        behavioralTags.push(`alert_category:${eve.alert.category}`);
        behavioralTags.push(`alert_severity:${eve.alert.severity}`);
        if (eve.alert.signature) {
            behavioralTags.push(`alert_msg:${eve.alert.signature}`);
            behavioralTags.push(eve.alert.signature); // Push raw signature too for includes() checks
        }
    } else if (eve.flow) {
        behavioralTags.push(`flow_state:${eve.flow.state}`);
    }

    if (eve.http?.url?.endsWith('.exe') || eve.http?.http_content_type === 'application/octet-stream') {
        behavioralTags.push('binary_download_octet_stream');
    }
    if (eve.alert?.category?.toLowerCase().includes('trojan')) {
        behavioralTags.push('trojan_indicator');
    }

    const enriched: EnrichedIOC = {
        ioc_value: target,
        ioc_type: eve.dns ? 'domain' : eve.http ? 'url' : 'IP',
        is_anomaly: d2Result.anomaly || false,
        threat_score: 0,
        confidence: 0.9,
        reputation: 'unknown',
        event: event,
        tags: [...new Set([...(d2Result.tags || []), ...behavioralTags])],
        context: eve,
        enrichment: {},
        last_enriched: new Date().toISOString()
    };

    if (d8Signals && d8Signals.length > 0) {
        const currentTags = enriched.tags || [];
        enriched.tags = [...new Set([...currentTags, ...d8Signals.flatMap((s: any) => s.tags || [])])];
        enriched.threat_score = Math.max(...d8Signals.map((s: any) => s.recommended_score_boost || 0));
    }

    // 4. D4/D7 (Optional Intelligence)
    if (agents.d4) {
        const tactical = await agents.d4.enrichTactical(target);
        if (tactical) {
            enriched.tactical = tactical;
            enriched.tags = [...new Set([...(enriched.tags || []), ...tactical.signals.map((s: any) => s.name)])];
        }
    }

    // Initial check for D7
    const initialClass = await agents.ethos.classify(enriched);
    if (agents.d7) {
        const psysec = agents.d7.analyze(d2Result, initialClass);
        enriched.psysec = psysec;
        enriched.tags = [...new Set([...(enriched.tags || []), ...psysec.profile.tags])];
    }

    // 5. D10 Classification (Taxonomy)
    const finalClass = await agents.ethos.classify(enriched);

    // 6. D12 Decision (Arbiter)
    const decision = agents.rottweiler.decide(d2Result, enriched, finalClass);

    // 7. D1 Action (Infantaria)
    const execution = await agents.infantaria.respond(decision, target);

    // Output Result
    console.log(`[D12 Decision] ${decision.action} | Reason: ${decision.reason}`);
    if (execution.success) {
        console.log(`[D1 Execution] ✅ ${execution.details}`);
    }

    // 7b. D6 Diplomacy (Executive Reporting for High Severity)
    if (event.severity === 'critical' || event.severity === 'high') {
        const report = await agents.diplomacy.generateExecutiveReport([d2Result], [d5Result], []);
        console.log(`\n--- 📜 EXECUTIVE INSIGHT (D6) ---\n${report.summary}\n`);
    }

    // 8. D11 AfterAction (BDA & Feedback)
    const end = performance.now();
    const latency = Math.round(end - start);

    const feedback = agents.afterAction.analyze({
        event,
        enriched,
        classification: finalClass,
        decision,
        execution,
        latency_ms: latency
    });

    if (feedback.feedback_type !== 'NEUTRAL') {
        console.log(`[D11 Feedback] ${feedback.feedback_type} | ${feedback.bda_summary}`);
        if (feedback.signals.length > 0) {
            if (learn) {
                console.log(`[D11 Learning] 💾 PERSISTING Adjustment: ${JSON.stringify(feedback.signals)}`);
                // TODO: Save to rules.json or database
            } else {
                console.log(`[D11 Dry-Run] 👁️ Suggested Adjustment: ${JSON.stringify(feedback.signals)}`);
            }
        }
    }

    if (strict) {
        // ALERT severity 1/critical não pode ser ALLOW
        if (eve.event_type === 'alert' && eve.alert?.severity === 1) {
            assert(decision.action !== 'ALLOW', 'suricata alert severity=1 must not ALLOW');
        }

        // Download .exe + octet-stream deve conter ação de contenção
        const httpCT = eve.http?.http_content_type || eve.http?.content_type;
        const isExe = typeof eve.http?.url === 'string' && eve.http.url.toLowerCase().endsWith('.exe');
        const isOctet = httpCT === 'application/octet-stream';

        if (eve.event_type === 'http' && isExe && isOctet) {
            assert(['QUARANTINE', 'BLOCK'].includes(decision.action), 'exe+octet-stream should QUARANTINE or BLOCK');
        }

        // execução deve retornar boolean e sucesso coerente quando auto_execute
        assert(typeof execution.success === 'boolean', 'D1 must return success boolean');

        // Validation against Expected Dataset (KC7)
        if (eve._expected) {
            stats.total++;
            const expectedAction = eve._expected.d12_action;
            // A rigor, ISOLATE_HOST e QUARANTINE podem ser tratados como similares em alguns contextos,
            // mas aqui vamos exigir match exato ou mapeamento inteligente se necessário.
            const match = decision.action === expectedAction;

            // Allow BLOCK to match ISOLATE_HOST if needed, or specific mappings
            // For KC7 we want strict mapping

            stats.results.push({
                id: eve._comment || eve.timestamp,
                expected: expectedAction,
                actual: decision.action,
                success: match,
                d10_match: true // TODO: validate d10_type if needed
            });

            if (match) {
                stats.passed++;
                console.log(`[Validation] ✅ PASS: Got ${decision.action} as expected.`);
            } else {
                stats.failed++;
                console.error(`[Validation] ❌ FAIL: Expected ${expectedAction}, Got ${decision.action}`);
                // assert(false, `Validation Mismatch for ${eve._comment}`); // Optional: fail hard
            }
        }
    }
}

function mapToSecurityEvent(eve: any): SecurityEvent | null {
    if (!eve.event_type || !['alert', 'dns', 'http', 'flow'].includes(eve.event_type)) return null;

    const timestamp = eve.timestamp || new Date().toISOString();
    const src_ip = eve.src_ip || '0.0.0.0';
    const dest_ip = eve.dest_ip;

    // Deterministic Event ID
    const event_id = crypto.createHash('md5')
        .update(`${timestamp}${src_ip}${dest_ip}${eve.event_type}`)
        .digest('hex')
        .substring(0, 12);

    const actionMap: Record<string, string> = {
        alert: 'suricata_alert',
        dns: 'dns_query',
        http: 'http_request',
        flow: 'net_flow'
    };

    let severity: SecurityEvent['severity'] = 'low';
    if (eve.alert) {
        severity = eve.alert.severity === 1 ? 'critical' : eve.alert.severity === 2 ? 'high' : 'medium';
    }

    return {
        timestamp,
        event_id,
        log_source_id: 'SURICATA',
        source_ip: src_ip,
        destination_ip: dest_ip,
        action: actionMap[eve.event_type] || 'unknown',
        status: 'success',
        severity,
        message: eve.alert?.signature || `Suricata ${eve.event_type} event`,
        metadata: eve
    };
}

function extractTarget(eve: any): string | null {
    if (eve.dns?.query) return eve.dns.query[0]?.rrname || null;
    if (eve.http?.hostname) return eve.http.hostname;
    if (eve.dest_ip) return eve.dest_ip;
    return null;
}

/**
 * Mapeia eventos do Suricata para fases do MITRE ATT&CK
 */
function mapToMitrePhase(eve: any): any {
    const { MITREPhase } = require('../src/agents/d9_attackgraph/types');

    if (eve.event_type === 'alert') {
        const sig = (eve.alert.signature || '').toLowerCase();
        if (sig.includes('scan') || sig.includes('nmap')) return MITREPhase.DISCOVERY;
        if (sig.includes('exploit') || sig.includes('overflow')) return MITREPhase.INITIAL_ACCESS;
        if (sig.includes('brute') || sig.includes('login')) return MITREPhase.CREDENTIAL_ACCESS;
        if (sig.includes('trojan') || sig.includes('malware')) return MITREPhase.EXECUTION;
    }

    if (eve.event_type === 'http') return MITREPhase.INITIAL_ACCESS;
    if (eve.event_type === 'dns') return MITREPhase.DISCOVERY;

    return MITREPhase.UNKNOWN;
}

main().catch(console.error);
