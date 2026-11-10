import * as fs from "fs";
import * as readline from "readline";

import { DalionSentinela } from "../src/agents/d2_sentinela/index";
import { DalionEthos } from '../src/agents/d10_ethos/index';
import { DalionRottweiler } from '../src/agents/d12_rottweiler/index';
import { DalionInfantaria } from '../src/agents/d1_infantaria/index';
import { DalionThreatIntel } from "../src/agents/d8_threatintel/index";
import { DalionIntelCampo } from '../src/agents/d4_intel_campo/index';
import { DalionPsySec } from '../src/agents/d7_psysec/index';
import { DetectionResult } from '../src/agents/d2_sentinela/types';
import { ClassificationResult } from '../src/agents/d10_ethos/types';
import { StrategicDecision } from '../src/agents/d12_rottweiler/types';
import { ExecutionResult } from '../src/agents/d1_infantaria/types';

// D3 é opcional (depende de chaves). Se quiser incluir, descomente.
// import { DalionEspionagem } from "../src/agents/d3_espionagem/index";

type LabEvent = {
    timestamp: string;
    event_id: string;
    log_source_id: string;
    source_ip: string;
    action: string;
    status: string;
    severity: string;
    message: string;
    context: Record<string, any>;
    expected: { threat_type: string; action: string };
};

function assert(cond: any, msg: string) {
    if (!cond) {
        console.error(`❌ ASSERT FAILED: ${msg} `);
        process.exitCode = 1;
    } else {
        console.log(`✅ ASSERT: ${msg} `);
    }
}

function safeStr(x: any) {
    return typeof x === "string" ? x : JSON.stringify(x);
}

async function main() {
    const datasetPath = process.argv[2] || "mini-kc7/lab_dataset.jsonl";
    if (!fs.existsSync(datasetPath)) {
        console.error(`Dataset not found: ${datasetPath} `);
        process.exit(1);
    }

    console.log("=== 🧪 MINI-KC7 LOCAL VALIDATION ===");
    console.log(`Dataset: ${datasetPath} \n`);

    // Initialize agents (no external side-effects)
    const d2 = new DalionSentinela();
    const d8 = new DalionThreatIntel();
    const ethos = new DalionEthos();
    const rottweiler = new DalionRottweiler();
    const infantaria = new DalionInfantaria({
        auto_execute: true,
        require_approval_for: ["ISOLATE_HOST"], // safety
    });
    const intelCampo = new DalionIntelCampo();
    const psySec = new DalionPsySec();

    const rl = readline.createInterface({
        input: fs.createReadStream(datasetPath),
        crlfDelay: Infinity,
    });

    let total = 0;
    let correctAction = 0;
    let correctType = 0;

    const actionCounts: Record<string, number> = {};
    const typeCounts: Record<string, number> = {};
    const mismatches: any[] = [];

    for await (const line of rl) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        total++;
        const ev = JSON.parse(trimmed) as LabEvent;

        // --- D2 analyze ---
        const d2Result: DetectionResult = await d2.analyze(ev as any);

        // Pick target IOC from event context with fallback to event_id
        const target =
            ev.context?.url ||
            ev.context?.domain ||
            ev.context?.dst_ip ||
            ev.context?.process ||
            ev.context?.key ||
            ev.context?.command ||
            ev.context?.pattern ||
            `event:${ev.event_id} `;

        // --- D8 enrich (mock hub) ---
        const d8Signals = await d8.lookup(String(target));
        const enrichedIOC: any = {
            ioc_value: String(target),
            ioc_type: ev.context?.url ? 'url' : ev.context?.dst_ip ? 'IP' : 'domain',
            threat_score: 0,
            tags: d2Result.tags || [], // Carry over D2 heuristic tags
            enrichment: { virustotal: {}, abuseipdb: {} },
            anomaly: d2Result?.anomaly ?? false,
            severity: ev.severity,
            source: ev.log_source_id,
            context: ev.context, // Propagate full context for D10 taxonomy
            confidence: 0.9 // High confidence for lab signals
        };

        if (d8Signals.length > 0) {
            enrichedIOC.tags = [
                ...(enrichedIOC.tags || []),
                ...d8Signals.flatMap((s: any) => s.tags || []),
            ];
            const maxBoost = Math.max(
                ...d8Signals.map((s: any) => s.recommended_score_boost ?? 0),
                0
            );
            enrichedIOC.threat_score = Math.max(enrichedIOC.threat_score, maxBoost);
        }
        if (d8Signals.length > 0) {
            enrichedIOC.enrichment = { virustotal: d8Signals[0] };
        }

        // --- PHASE 10: ADVANCED INTEL & PSYSEC ---
        const d4Intel = await intelCampo.enrichTactical(target);
        if (d4Intel) {
            enrichedIOC.tactical = d4Intel;
            enrichedIOC.tags = [...(enrichedIOC.tags || []), ...d4Intel.signals.map(s => s.name)];
        }

        // Classification for PsySec context
        const initialClass = await ethos.classify(enrichedIOC);
        const d7Analysis = psySec.analyze(d2Result, initialClass);
        enrichedIOC.psysec = d7Analysis;
        enrichedIOC.tags = [...(enrichedIOC.tags || []), ...d7Analysis.profile.tags];

        // --- CLASSIFICATION (D10 with full context) ---
        const finalClass: ClassificationResult = await ethos.classify(enrichedIOC);

        // --- D12 decide ---
        const decision: StrategicDecision = rottweiler.decide(d2Result, enrichedIOC, finalClass);

        // --- D1 respond (simulated execution) ---
        const exec: ExecutionResult = await infantaria.respond(decision, String(target));

        // bookkeeping
        actionCounts[decision.action] = (actionCounts[decision.action] || 0) + 1;
        typeCounts[finalClass.threat_type] = (typeCounts[finalClass.threat_type] || 0) + 1;

        const okAction = decision.action === ev.expected.action;
        const okType = String(finalClass.threat_type).toLowerCase() === ev.expected.threat_type.toLowerCase();

        if (okAction) correctAction++;
        if (okType) correctType++;

        if (!okAction || !okType) {
            mismatches.push({
                event_id: ev.event_id,
                expected: ev.expected,
                got: { threat_type: finalClass.threat_type, action: decision.action },
                target,
                reason: decision.reason,
                exec: { success: exec.success, details: exec.details },
            });
        }
    }

    // ---- Report ----
    console.log("\n=== 📊 MINI-KC7 REPORT ===");
    console.log(`Events: ${total} `);
    console.log(`Type accuracy: ${(correctType / total * 100).toFixed(1)}% `);
    console.log(`Action accuracy: ${(correctAction / total * 100).toFixed(1)}% `);

    console.log("\nActions:");
    Object.entries(actionCounts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([k, v]) => console.log(`  ${k}: ${v} `));

    console.log("\nThreat types:");
    Object.entries(typeCounts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([k, v]) => console.log(`  ${k}: ${v} `));

    if (mismatches.length) {
        console.log(`\n⚠️ Mismatches(${mismatches.length}): `);
        mismatches.slice(0, 10).forEach((m) => {
            console.log(`- ${m.event_id} target = ${safeStr(m.target)} `);
            console.log(`  expected: ${m.expected.threat_type}/${m.expected.action}`);
            console.log(`  got:      ${m.got.threat_type.toUpperCase()}/${m.got.action}`);
            console.log(`  reason:   ${m.reason}`);
            console.log(`  exec:     ${m.exec.success ? "SUCCESS" : "PENDING/FAIL"} | ${m.exec.details}`);
        });
    }

    // ---- Scientific acceptance gate ----
    const typeAcc = correctType / Math.max(1, total);
    const actionAcc = correctAction / Math.max(1, total);

    assert(typeAcc >= 0.60, `Type accuracy should be >= 60% (got ${(typeAcc * 100).toFixed(1)}%)`);
    assert(actionAcc >= 0.60, `Action accuracy should be >= 60% (got ${(actionAcc * 100).toFixed(1)}%)`);

    console.log("\n✅ Mini-KC7 finished.");
}

main().catch((e) => {
    console.error("Runner crashed:", e);
    process.exit(1);
});
