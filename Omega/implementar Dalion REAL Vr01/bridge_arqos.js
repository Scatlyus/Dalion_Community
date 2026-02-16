#!/usr/bin/env node

/**
 * Dalion → Arqos Bridge
 * 
 * Converts Dalion agent specs (.md with YAML frontmatter)
 * into Arqos Engine axioms (YAML format).
 * 
 * Usage:
 *   node tools/bridge_arqos.js
 *   node tools/bridge_arqos.js --agent=d2_sentinela
 *   node tools/bridge_arqos.js --tier=starter
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
  // Check if has frontmatter
  if (!content.startsWith('---\n')) {
    throw new Error('No YAML frontmatter found');
  }

  // Extract frontmatter
  const endOfFrontmatter = content.indexOf('\n---\n', 4);
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

  // Build Arqos axiom structure
  const axiom = {
    // Metadata
    id: `dalion_${agentName}`,
    version: frontmatter.version || '1.0.0',
    name: frontmatter.name || agentName,
    description: frontmatter.description || '',
    author: frontmatter.author || 'Dalion Team',
    
    // Classification
    category: 'security',
    tier: frontmatter.tier || 'starter',
    
    // Dependencies
    dependencies: frontmatter.dependencies || [],
    
    // Execution
    handler: {
      type: 'node',
      entry: `agents/${agentName}/index.js`,
      timeout: frontmatter.timeout || 30000
    },
    
    // Input/Output schemas
    input_schema: frontmatter.input_schema || {},
    output_schema: frontmatter.output_schema || {},
    
    // Observability
    observability: frontmatter.observability || {
      logging: true,
      metrics: true,
      tracing: false
    },
    
    // Error handling
    error_handling: frontmatter.error_handling || {
      strategy: 'retry',
      max_retries: 3,
      fallback: 'log_and_continue'
    },
    
    // ATLAS protocol
    atlas: {
      cognitive_tier: determineCognitiveTier(agentName),
      governance_level: determineGovernanceLevel(agentName),
      memory_enabled: true
    }
  };

  return axiom;
}

/**
 * Determine cognitive tier based on agent name
 */
function determineCognitiveTier(agentName) {
  const tierMap = {
    d1_infantaria: 'T1', // Response
    d2_sentinela: 'T0',  // Detection
    d3_espionagem: 'T2', // Enrichment
    d4_intel_campo: 'T3', // Analysis
    d5_artilharia: 'T2', // Enforcement
    d6_diplomacia: 'T4', // Reporting
    d7_psysec: 'T3',     // Advanced detection
    d8_threatintel: 'T2', // Threat intel
    d9_attackgraph: 'T3', // Prediction
    d10_ethos: 'T2',     // Classification
    d11_afteraction: 'T4', // Learning
    d12_rottweiler: 'T1'  // Containment
  };

  return tierMap[agentName] || 'T0';
}

/**
 * Determine governance level
 */
function determineGovernanceLevel(agentName) {
  const criticalAgents = ['d12_rottweiler', 'd11_afteraction', 'd5_artilharia'];
  return criticalAgents.includes(agentName) ? 'high' : 'medium';
}

/**
 * Process single agent
 */
function processAgent(tier, agentFile) {
  const agentPath = path.join(DALION_PACKS, tier, 'agents', agentFile);
  
  if (!fs.existsSync(agentPath)) {
    log(`  ⚠️  File not found: ${agentPath}`, 'yellow');
    return false;
  }

  try {
    const content = fs.readFileSync(agentPath, 'utf8');
    const agentSpec = parseMarkdownWithFrontmatter(content);
    
    const agentName = path.basename(agentFile, '.md');
    const axiom = convertToArqosAxiom(agentSpec, agentName);
    
    // Write to Arqos axioms directory
    const axiomPath = path.join(ARQOS_AXIOMS, `${axiom.id}.yaml`);
    fs.writeFileSync(axiomPath, yaml.dump(axiom), 'utf8');
    
    log(`  ✅ ${agentName} → ${axiom.id}.yaml`, 'green');
    return true;
  } catch (error) {
    log(`  ❌ Error processing ${agentFile}: ${error.message}`, 'red');
    return false;
  }
}

/**
 * Main bridge function
 */
function bridge(options = {}) {
  log('\n🌉 Dalion → Arqos Bridge', 'cyan');
  log('Converting agent specs to axioms...\n', 'cyan');

  // Check if Arqos directory exists
  if (!fs.existsSync(ARQOS_AXIOMS)) {
    log(`❌ Arqos axioms directory not found: ${ARQOS_AXIOMS}`, 'red');
    log('Please clone Arqos Engine first:', 'yellow');
    log('  git clone https://github.com/Scatlyus/Arqos-Engine-FullStack.git arqos_engine\n', 'yellow');
    process.exit(1);
  }

  const stats = {
    processed: 0,
    success: 0,
    failed: 0
  };

  // Process tiers
  const tiers = options.tier ? [options.tier] : ['starter', 'pro', 'enterprise'];

  for (const tier of tiers) {
    const tierPath = path.join(DALION_PACKS, tier, 'agents');
    
    if (!fs.existsSync(tierPath)) {
      log(`⚠️  Tier not found: ${tier}`, 'yellow');
      continue;
    }

    log(`📦 Processing tier: ${tier}`, 'blue');

    const files = fs.readdirSync(tierPath)
      .filter(f => f.endsWith('.md'));

    for (const file of files) {
      // Filter by agent name if specified
      if (options.agent && !file.includes(options.agent)) {
        continue;
      }

      stats.processed++;
      const success = processAgent(tier, file);
      
      if (success) {
        stats.success++;
      } else {
        stats.failed++;
      }
    }
  }

  // Summary
  log('\n' + '='.repeat(50), 'cyan');
  log('📊 Bridge Summary', 'cyan');
  log('='.repeat(50), 'cyan');
  log(`Processed: ${stats.processed}`, 'blue');
  log(`Success:   ${stats.success}`, 'green');
  log(`Failed:    ${stats.failed}`, stats.failed > 0 ? 'red' : 'green');
  log('='.repeat(50) + '\n', 'cyan');

  if (stats.success > 0) {
    log('✅ Axioms generated successfully!', 'green');
    log(`📂 Location: ${ARQOS_AXIOMS}\n`, 'cyan');
  }

  return stats;
}

// Parse command line arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {};

  for (const arg of args) {
    if (arg.startsWith('--agent=')) {
      options.agent = arg.split('=')[1];
    } else if (arg.startsWith('--tier=')) {
      options.tier = arg.split('=')[1];
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
Dalion → Arqos Bridge

Usage:
  node tools/bridge_arqos.js [options]

Options:
  --agent=<name>   Process only specific agent (e.g., d2_sentinela)
  --tier=<name>    Process only specific tier (starter|pro|enterprise)
  --help, -h       Show this help message

Examples:
  node tools/bridge_arqos.js
  node tools/bridge_arqos.js --agent=d2_sentinela
  node tools/bridge_arqos.js --tier=starter
      `);
      process.exit(0);
    }
  }

  return options;
}

// Run if called directly
if (require.main === module) {
  const options = parseArgs();
  bridge(options);
}

module.exports = { bridge, convertToArqosAxiom };
