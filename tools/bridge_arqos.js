#!/usr/bin/env node

/**
 * Dalion → Arqos Bridge
 * 
 * Converts Dalion agent specs (.md with YAML frontmatter)
 * into Arqos Engine axioms (YAML format).
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// Paths
const DALION_PACKS = path.join(__dirname, '../packs');
const ARQOS_AXIOMS = path.join(__dirname, '../arqos_engine/packages/engine/src/core/axioms');

// Colors
const colors = {
    reset: '\x1b[0m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    red: '\x1b[31m',
    cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`);
}

/**
 * Parse Markdown file with YAML frontmatter
 */
function parseMarkdownWithFrontmatter(content) {
    if (!content.startsWith('---\n') && !content.startsWith('---\r\n')) {
        throw new Error('No YAML frontmatter found');
    }

    const endOfFrontmatter = content.indexOf('\n---\n', 4) !== -1 ?
        content.indexOf('\n---\n', 4) :
        content.indexOf('\r\n---\r\n', 4);

    if (endOfFrontmatter === -1) {
        throw new Error('Invalid frontmatter format');
    }

    const frontmatterText = content.substring(4, endOfFrontmatter);
    const bodyText = content.substring(endOfFrontmatter + 5);

    const frontmatter = yaml.load(frontmatterText);

    return {
        frontmatter,
        body: bodyText
    };
}

/**
 * Convert Dalion agent spec to Arqos axiom format
 */
function convertToArqosAxiom(agentSpec, agentName) {
    const { frontmatter } = agentSpec;

    const axiom = {
        id: `dalion_${agentName}`,
        version: frontmatter.version || '1.0.0',
        name: frontmatter.name || agentName,
        description: frontmatter.description || '',
        author: frontmatter.author || 'Dalion Team',
        category: 'security',
        tier: frontmatter.tier || 'starter',
        dependencies: frontmatter.dependencies || [],
        handler: {
            type: 'node',
            entry: `agents/${agentName}/index.js`,
            timeout: frontmatter.timeout || 30000
        },
        input_schema: frontmatter.input_schema || {},
        output_schema: frontmatter.output_schema || {},
        observability: frontmatter.observability || {
            logging: true,
            metrics: true,
            tracing: false
        },
        error_handling: frontmatter.error_handling || {
            strategy: 'retry',
            max_retries: 3,
            fallback: 'log_and_continue'
        },
        atlas: {
            cognitive_tier: determineCognitiveTier(agentName),
            governance_level: determineGovernanceLevel(agentName),
            memory_enabled: true
        }
    };

    return axiom;
}

function determineCognitiveTier(agentName) {
    const tierMap = {
        d1_infantaria: 'T1',
        d2_sentinela: 'T0',
        d3_espionagem: 'T2',
        d4_intel_campo: 'T3',
        d5_artilharia: 'T2',
        d6_diplomacia: 'T4',
        d7_psysec: 'T3',
        d8_threatintel: 'T2',
        d9_attackgraph: 'T3',
        d10_ethos: 'T2',
        d11_afteraction: 'T4',
        d12_rottweiler: 'T1'
    };
    return tierMap[agentName] || 'T0';
}

function determineGovernanceLevel(agentName) {
    const criticalAgents = ['d12_rottweiler', 'd11_afteraction', 'd5_artilharia'];
    return criticalAgents.includes(agentName) ? 'high' : 'medium';
}

function processAgent(tier, agentFile) {
    const agentPath = path.join(DALION_PACKS, tier, 'agents', agentFile);
    if (!fs.existsSync(agentPath)) return false;

    try {
        const content = fs.readFileSync(agentPath, 'utf8');
        const agentSpec = parseMarkdownWithFrontmatter(content);
        const agentName = path.basename(agentFile, '.md').toLowerCase();
        const axiom = convertToArqosAxiom(agentSpec, agentName);

        // Create axioms directory if not exists
        if (!fs.existsSync(ARQOS_AXIOMS)) {
            fs.mkdirSync(ARQOS_AXIOMS, { recursive: true });
        }

        const axiomPath = path.join(ARQOS_AXIOMS, `${axiom.id}.yaml`);
        fs.writeFileSync(axiomPath, yaml.dump(axiom), 'utf8');
        log(`  ✅ ${agentName} → ${axiom.id}.yaml`, 'green');
        return true;
    } catch (error) {
        log(`  ❌ Error processing ${agentFile}: ${error.message}`, 'red');
        return false;
    }
}

function bridge(options = {}) {
    log('\n🌉 Dalion → Arqos Bridge (Real Path)', 'cyan');

    const stats = { processed: 0, success: 0, failed: 0 };
    const tiers = options.tier ? [options.tier] : ['starter', 'pro', 'enterprise'];

    for (const tier of tiers) {
        const tierPath = path.join(DALION_PACKS, tier, 'agents');
        if (!fs.existsSync(tierPath)) continue;

        log(`📦 Processing tier: ${tier}`, 'blue');
        const files = fs.readdirSync(tierPath).filter(f => f.endsWith('.md'));

        for (const file of files) {
            if (options.agent && !file.includes(options.agent)) continue;
            stats.processed++;
            if (processAgent(tier, file)) stats.success++; else stats.failed++;
        }
    }

    log(`\nProcessed: ${stats.processed} | Success: ${stats.success} | Failed: ${stats.failed}`, 'blue');
}

bridge();
