#!/usr/bin/env node
/**
 * Dalion Claim Verifier
 * Verifica se as claims do "Wave 2 concluída" estão suportadas por código real:
 * - D8 ThreatIntel Hub existe e tem implementação?
 * - D1 Infantaria existe e executa algo (mesmo mock)?
 * - Pipeline referencia D8/D1?
 * - Existem sinais de "bloqueio" e "intel hub" no código, não só em texto?
 */

const fs = require("fs");
const path = require("path");

const root = path.resolve(process.argv[2] || process.cwd());
const IGNORE = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);
const CODE_EXT = new Set([".ts", ".js", ".mjs", ".cjs"]);

const PLACEHOLDER_RX = [
    /\bTODO\b/i,
    /\bFIXME\b/i,
    /\bplaceholder\b/i,
    /\bnot implemented\b/i,
    /throw new Error\(\s*["'`]NotImplemented/i,
    /\bTBD\b/i,
];

function walk(dir, out = []) {
    let items = [];
    try { items = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
    for (const it of items) {
        if (IGNORE.has(it.name)) continue;
        const full = path.join(dir, it.name);
        if (it.isDirectory()) walk(full, out);
        else out.push(full);
    }
    return out;
}

function read(p) {
    try { return fs.readFileSync(p, "utf8"); } catch { return ""; }
}

function isCodeFile(p) {
    return CODE_EXT.has(path.extname(p));
}

function fileStats(p) {
    const txt = read(p);
    const lines = txt.split(/\r?\n/);
    const meaningful = lines.filter(l => {
        const t = l.trim();
        if (!t) return false;
        if (t.startsWith("//")) return false;
        if (t.startsWith("/*") || t.startsWith("*") || t.startsWith("*/")) return false;
        return true;
    });

    const placeholderHits = PLACEHOLDER_RX.reduce((acc, rx) => acc + (rx.test(txt) ? 1 : 0), 0);
    const signals =
        (/\b(import|export)\b/.test(txt) ? 1 : 0) +
        (/\brequire\(/.test(txt) ? 1 : 0) +
        (/\bclass\b/.test(txt) ? 1 : 0) +
        (/\bfunction\b/.test(txt) ? 1 : 0) +
        (/\basync\b/.test(txt) ? 1 : 0) +
        (/\bawait\b/.test(txt) ? 1 : 0);

    return {
        loc: meaningful.length,
        placeholderHits,
        signals,
        isStub: meaningful.length < 12 || (signals <= 1 && placeholderHits > 0),
        text: txt,
    };
}

function findPathsLike(subpath) {
    const p = path.join(root, subpath);
    if (!fs.existsSync(p)) return [];
    const all = walk(p).filter(isCodeFile);
    return all;
}

function searchAllCode(patterns) {
    const all = walk(root).filter(isCodeFile);
    const hits = [];
    for (const f of all) {
        const txt = read(f);
        for (const ptn of patterns) {
            if (ptn.test(txt)) {
                hits.push({ file: path.relative(root, f).replace(/\\/g, "/"), match: ptn.toString() });
                break;
            }
        }
    }
    return hits;
}

function summarizeAgent(agentName, agentPath) {
    const files = findPathsLike(agentPath);
    const entry = files.find(f => /\/(index|main|agent)\.(ts|js)$/.test(f.replace(/\\/g, "/"))) || null;

    const analyzed = files.map(f => ({
        file: path.relative(root, f).replace(/\\/g, "/"),
        ...fileStats(f),
    }));

    const total = analyzed.length;
    const stubs = analyzed.filter(a => a.isStub).length;
    const placeholders = analyzed.filter(a => a.placeholderHits > 0).length;
    const avgLOC = total ? Math.round(analyzed.reduce((s, a) => s + a.loc, 0) / total) : 0;

    const implScore =
        total === 0 ? 0 :
            Math.max(0, Math.min(1, (avgLOC / 40) * 0.6 + ((1 - placeholders / total) * 0.4) - (stubs / total) * 0.3));

    return {
        agentName,
        agentPath,
        exists: total > 0,
        entry: entry ? path.relative(root, entry).replace(/\\/g, "/") : null,
        totalFiles: total,
        stubFiles: stubs,
        placeholderFiles: placeholders,
        avgLOC,
        implScore: Number(implScore.toFixed(2)),
        topFiles: analyzed
            .sort((a, b) => (b.placeholderHits + (b.isStub ? 2 : 0)) - (a.placeholderHits + (a.isStub ? 2 : 0)))
            .slice(0, 6)
            .map(a => ({ file: a.file, loc: a.loc, placeholders: a.placeholderHits, signals: a.signals, stub: a.isStub })),
    };
}

function verdict(agentSummary) {
    if (!agentSummary.exists) return "MISSING";
    if (!agentSummary.entry) return "NO_ENTRY";
    if (agentSummary.implScore < 0.45) return "PLACEHOLDER";
    if (agentSummary.implScore < 0.70) return "PARTIAL";
    return "IMPLEMENTED";
}

function main() {
    console.log(`\n🔬 Dalion Claim Verifier`);
    console.log(`📍 Root: ${root}\n`);

    const d8 = summarizeAgent("D8 ThreatIntel", "src/agents/d8_threatintel");
    const d1 = summarizeAgent("D1 Infantaria", "src/agents/d1_infantaria");

    const refs = searchAllCode([
        /d8_threatintel/i,
        /ThreatIntel/i,
        /intel_match/i,
        /embedded_pdf_phishing/i,
        /d1_infantaria/i,
        /Infantaria/i,
        /firewall/i,
        /\bblock\b/i,
        /\bexecute\b/i,
    ]);

    const d8v = verdict(d8);
    const d1v = verdict(d1);

    console.log(`🛰️ D8: ${d8v}`);
    console.log(d8);

    console.log(`\n⚔️ D1: ${d1v}`);
    console.log(d1);

    console.log(`\n🔎 Referências no código (prova de integração):`);
    if (refs.length === 0) console.log("  • Nenhuma referência encontrada (sinal de desconexão do pipeline).");
    else refs.slice(0, 30).forEach(h => console.log(`  • ${h.file}  (${h.match})`));

    // Claim-level verdict
    const claimOK =
        (d8v === "IMPLEMENTED" || d8v === "PARTIAL") &&
        (d1v === "IMPLEMENTED" || d1v === "PARTIAL") &&
        refs.length > 0;

    console.log(`\n🏁 CLAIM VERDICT: ${claimOK ? "SUPPORTED (há evidência no código)" : "NOT SUPPORTED (texto > evidência)"}`);

    if (!claimOK) {
        console.log("\nDiagnosis:");
        if (d8v === "MISSING") console.log("  • D8 não existe no código.");
        if (d8v === "PLACEHOLDER") console.log("  • D8 existe, mas parece placeholder.");
        if (d1v === "MISSING") console.log("  • D1 não existe no código.");
        if (d1v === "PLACEHOLDER") console.log("  • D1 existe, mas parece placeholder.");
        if (refs.length === 0) console.log("  • Não há sinais de integração (D8/D1 não aparecem no pipeline).");
    }

    process.exitCode = claimOK ? 0 : 1;
}

main();
