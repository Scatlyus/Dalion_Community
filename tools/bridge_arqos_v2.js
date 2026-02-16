#!/usr/bin/env node

/**
 * Dalion → Arqos Bridge V2
 * 
 * Converts Dalion agent specs (Markdown + YAML frontmatter)
 * into Arqos Engine axioms (YAML format).
 * 
 * Features:
 * - Validation of input specs
 * - Cognitive tier mapping (T0-T4)
 * - Governance level assignment
 * - Schema generation
 * - Error handling
 * 
 * Usage:
 *   node tools/bridge_arqos_v2.js
 *   node tools/bridge_arqos_v2.js --agent=d2_sentinela
 *   node tools/bridge_arqos_v2.js --tier=starter
 *   node tools/bridge_arqos_v2.js --validate-only
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

// Colors
const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// Paths
const DALION_PACKS = path.join(__dirname, '../packs');
const ARQOS_AXIOMS = path.join(__dirname, '../arqos_engine/packages/engine/src/core/axioms');
const SRC_AGENTS = path.join(__dirname, '../src/agents');

/**
 * Parse Markdown file with YAML frontmatter
 */
function parseMarkdownWithFrontmatter(content) {
  // Normalize line endings to avoid issues with startsWith/indexOf
  const normalized = content.replace(/\r\n/g, '\n');

  if (!normalized.startsWith('---\n')) {
    throw new Error('No YAML frontmatter found (must start with "---")');
  }

  const endOfFrontmatter = normalized.indexOf('\n---\n', 4);
  if (endOfFrontmatter === -1) {
    throw new Error('Invalid frontmatter format (missing closing "---")');
  }

  const frontmatterText = normalized.substring(4, endOfFrontmatter);
  const bodyText = normalized.substring(endOfFrontmatter + 5);

  let frontmatter;
  try {
    frontmatter = yaml.load(frontmatterText);
  } catch (error) {
    throw new Error(`Invalid YAML in frontmatter: ${error.message}`);
  }

  return {
    frontmatter,
    body: bodyText
  };
}

/**
 * Determine cognitive tier based on agent name or code
 */
function determineCognitiveTier(agentName) {
  const normalized = agentName.toLowerCase();

  // Mapping based on common codes/keywords
  if (normalized.includes('snt') || normalized.includes('sentinela')) return 'T0';
  if (normalized.includes('infantaria')) return 'T1';
  if (normalized.includes('rot') || normalized.includes('rottweiler')) return 'T1';
  if (normalized.includes('esp') || normalized.includes('espionagem')) return 'T2';
  if (normalized.includes('art') || normalized.includes('artilharia')) return 'T2';
  if (normalized.includes('intel') || normalized.includes('threat')) return 'T2';
  if (normalized.includes('ethos')) return 'T2';
  if (normalized.includes('ico') || normalized.includes('campo')) return 'T3';
  if (normalized.includes('psy')) return 'T3';
  if (normalized.includes('gra') || normalized.includes('graph')) return 'T3';
  if (normalized.includes('dip') || normalized.includes('diplomacia')) return 'T4';
  if (normalized.includes('aft') || normalized.includes('afteraction')) return 'T4';

  return 'T0';
}

/**
 * Determine governance level based on agent criticality
 */
function determineGovernanceLevel(agentName, tier) {
  // Critical agents (can block/modify/learn)
  const criticalAgents = [
    'd12_rottweiler',  // Containment
    'd11_afteraction', // ML learning
    'd5_artilharia',   // Compliance enforcement
    'd1_infantaria'    // Fast response
  ];

  if (criticalAgents.includes(agentName.toLowerCase())) {
    return 'high';
  }

  // Sensitive agents (enrichment, classification)
  const sensitiveAgents = [
    'd3_espionagem',
    'd10_ethos',
    'd9_attackgraph'
  ];

  if (sensitiveAgents.includes(agentName.toLowerCase())) {
    return 'medium';
  }

  // Standard monitoring
  return 'low';
}

/**
 * Map Dalion tier to Arqos deployment profile
 */
function mapDeploymentProfile(dalionTier) {
  const profileMap = {
    starter: 'development',
    pro: 'staging',
    enterprise: 'production'
  };

  return profileMap[dalionTier.toLowerCase()] || 'development';
}

/**
 * Extract implementation path if exists
 */
function findImplementationPath(agentName) {
  const normalized = agentName.toLowerCase();
  let code = null;

  // Map specialized names to standard codes
  if (normalized.includes('snt') || normalized.includes('sentinela')) code = 'd2_sentinela';
  if (normalized.includes('esp') || normalized.includes('espionagem')) code = 'd3_espionagem';
  if (normalized.includes('infantaria')) code = 'd1_infantaria';
  if (normalized.includes('rot')) code = 'd12_rottweiler';
  if (normalized.includes('art')) code = 'd5_artilharia';
  if (normalized.includes('ethos')) code = 'd10_ethos';

  const possiblePaths = [];

  if (code) {
    possiblePaths.push(path.join(SRC_AGENTS, code, 'index.ts'));
    possiblePaths.push(path.join(SRC_AGENTS, code, 'index.js'));
  }

  possiblePaths.push(path.join(SRC_AGENTS, agentName, 'index.ts'));
  possiblePaths.push(path.join(SRC_AGENTS, agentName.replace('_', '-'), 'index.ts'));

  for (const implPath of possiblePaths) {
    if (fs.existsSync(implPath)) {
      return path.relative(path.join(__dirname, '..'), implPath);
    }
  }

  return null;
}

/**
 * Convert Dalion agent spec to Arqos axiom format
 */
function convertToArqosAxiom(agentSpec, agentName, tier) {
  const { frontmatter, body } = agentSpec;

  // Basic validation
  if (!frontmatter.name) {
    throw new Error('Missing required field: name');
  }

  // Find implementation
  const implementationPath = findImplementationPath(agentName);
  const hasImplementation = implementationPath !== null;

  // Determine tiers
  const cognitiveTier = determineCognitiveTier(agentName);
  const governanceLevel = determineGovernanceLevel(agentName, tier);
  const deploymentProfile = mapDeploymentProfile(tier);

  // Build Arqos axiom structure
  const axiom = {
    // Metadata
    id: `dalion_${agentName}`,
    version: frontmatter.version || '1.0.0',
    name: frontmatter.name || agentName,
    description: frontmatter.description || '',
    author: frontmatter.author || 'Dalion Team',
    created_at: frontmatter.created_at || new Date().toISOString(),
    updated_at: new Date().toISOString(),

    // Classification
    category: 'security',
    subcategory: frontmatter.subcategory || 'threat_detection',
    tier: tier.toLowerCase(),
    deployment_profile: deploymentProfile,

    // Dependencies
    dependencies: frontmatter.dependencies || [],

    // Execution
    handler: hasImplementation ? {
      type: 'typescript',
      entry: implementationPath,
      timeout_ms: frontmatter.timeout || 30000,
      max_retries: 3
    } : {
      type: 'placeholder',
      message: 'Implementation pending',
      fallback: 'log_and_continue'
    },

    // Input/Output schemas
    input_schema: frontmatter.input_schema || {
      type: 'object',
      properties: {},
      required: []
    },

    output_schema: frontmatter.output_schema || {
      type: 'object',
      properties: {},
      required: []
    },

    // ATLAS protocol integration
    atlas: {
      cognitive_tier: cognitiveTier,
      governance_level: governanceLevel,
      memory_enabled: frontmatter.memory_enabled !== false,
      learning_enabled: cognitiveTier === 'T4',
      autonomy_level: frontmatter.autonomy_level || 'supervised'
    },

    // Observability
    observability: {
      logging: {
        enabled: true,
        level: frontmatter.log_level || 'info',
        structured: true
      },
      metrics: {
        enabled: true,
        prometheus: true,
        custom_metrics: frontmatter.custom_metrics || []
      },
      tracing: {
        enabled: deploymentProfile === 'production',
        sample_rate: 0.1
      }
    },

    // Error handling
    error_handling: {
      strategy: frontmatter.error_strategy || 'retry_with_backoff',
      max_retries: 3,
      retry_delay_ms: 1000,
      fallback: 'log_and_continue',
      circuit_breaker: {
        enabled: deploymentProfile === 'production',
        failure_threshold: 5,
        timeout_ms: 60000
      }
    },

    // Performance
    performance: {
      max_concurrent: frontmatter.max_concurrent || 10,
      queue_size: 1000,
      rate_limit: frontmatter.rate_limit || {
        requests: 100,
        window_ms: 60000
      }
    },

    // Security
    security: {
      authentication_required: deploymentProfile === 'production',
      authorization_required: governanceLevel === 'high',
      audit_trail: true,
      data_encryption: deploymentProfile === 'production'
    }
  };

  return axiom;
}

/**
 * Validate axiom against Arqos schema
 */
function validateAxiom(axiom) {
  const requiredFields = [
    'id',
    'version',
    'name',
    'category',
    'handler',
    'atlas'
  ];

  const errors = [];

  for (const field of requiredFields) {
    if (!(field in axiom)) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // Validate cognitive tier
  const validTiers = ['T0', 'T1', 'T2', 'T3', 'T4'];
  if (!validTiers.includes(axiom.atlas?.cognitive_tier)) {
    errors.push(`Invalid cognitive tier: ${axiom.atlas?.cognitive_tier}`);
  }

  // Validate governance level
  const validGovernance = ['low', 'medium', 'high'];
  if (!validGovernance.includes(axiom.atlas?.governance_level)) {
    errors.push(`Invalid governance level: ${axiom.atlas?.governance_level}`);
  }

  return errors;
}

/**
 * Process single agent
 */
function processAgent(tier, agentFile, options = {}) {
  const agentPath = path.join(DALION_PACKS, tier, 'agents', agentFile);

  if (!fs.existsSync(agentPath)) {
    log(`  ⚠️  File not found: ${agentPath}`, 'yellow');
    return { success: false, reason: 'not_found' };
  }

  try {
    const content = fs.readFileSync(agentPath, 'utf8');
    const agentSpec = parseMarkdownWithFrontmatter(content);

    const agentName = path.basename(agentFile, '.md');
    const axiom = convertToArqosAxiom(agentSpec, agentName, tier);

    // Validate
    const errors = validateAxiom(axiom);
    if (errors.length > 0) {
      log(`  ❌ Validation failed for ${agentName}:`, 'red');
      errors.forEach(err => log(`     - ${err}`, 'red'));
      return { success: false, reason: 'validation_failed', errors };
    }

    if (options.validateOnly) {
      log(`  ✅ ${agentName} → validation passed`, 'green');
      return { success: true, validated: true };
    }

    // Write to Arqos axioms directory
    const axiomPath = path.join(ARQOS_AXIOMS, `${axiom.id}.yaml`);
    fs.writeFileSync(axiomPath, yaml.dump(axiom, { indent: 2, lineWidth: 100 }), 'utf8');

    const hasImpl = axiom.handler.type !== 'placeholder';
    const implStatus = hasImpl ? '✅ (with impl)' : '⚠️  (placeholder)';

    log(`  ✅ ${agentName} → ${axiom.id}.yaml ${implStatus}`, 'green');

    return {
      success: true,
      axiomPath,
      hasImplementation: hasImpl,
      cognitiveTier: axiom.atlas.cognitive_tier,
      governanceLevel: axiom.atlas.governance_level
    };

  } catch (error) {
    log(`  ❌ Error processing ${agentFile}: ${error.message}`, 'red');
    return { success: false, reason: 'processing_error', error: error.message };
  }
}

/**
 * Main bridge function
 */
function bridge(options = {}) {
  log('\n🌉 Dalion → Arqos Bridge V2', 'magenta');
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
    failed: 0,
    with_implementation: 0,
    placeholder: 0,
    by_tier: {},
    by_governance: {}
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
      const result = processAgent(tier, file, options);

      if (result.success) {
        stats.success++;

        if (result.hasImplementation) {
          stats.with_implementation++;
        } else if (!result.validated) {
          stats.placeholder++;
        }

        // Track by cognitive tier
        if (result.cognitiveTier) {
          stats.by_tier[result.cognitiveTier] = (stats.by_tier[result.cognitiveTier] || 0) + 1;
        }

        // Track by governance level
        if (result.governanceLevel) {
          stats.by_governance[result.governanceLevel] = (stats.by_governance[result.governanceLevel] || 0) + 1;
        }
      } else {
        stats.failed++;
      }
    }
  }

  // Summary
  log('\n' + '='.repeat(70), 'magenta');
  log('📊 Bridge Summary', 'magenta');
  log('='.repeat(70), 'magenta');
  log(`Processed:           ${stats.processed}`, 'cyan');
  log(`Success:             ${stats.success}`, 'green');
  log(`Failed:              ${stats.failed}`, stats.failed > 0 ? 'red' : 'green');
  log(`With implementation: ${stats.with_implementation}`, 'green');
  log(`Placeholder:         ${stats.placeholder}`, 'yellow');

  if (Object.keys(stats.by_tier).length > 0) {
    log('\nBy Cognitive Tier:', 'cyan');
    Object.entries(stats.by_tier)
      .sort()
      .forEach(([tier, count]) => {
        log(`  ${tier}: ${count}`, 'cyan');
      });
  }

  if (Object.keys(stats.by_governance).length > 0) {
    log('\nBy Governance Level:', 'cyan');
    Object.entries(stats.by_governance)
      .sort()
      .forEach(([level, count]) => {
        log(`  ${level}: ${count}`, 'cyan');
      });
  }

  log('='.repeat(70) + '\n', 'magenta');

  if (stats.success > 0 && !options.validateOnly) {
    log('✅ Axioms generated successfully!', 'green');
    log(`📂 Location: ${ARQOS_AXIOMS}\n`, 'cyan');

    if (stats.placeholder > 0) {
      log(`⚠️  ${stats.placeholder} axiom(s) created without implementation`, 'yellow');
      log('   These will use placeholder handlers until code is available\n', 'yellow');
    }
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
    } else if (arg === '--validate-only') {
      options.validateOnly = true;
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
Dalion → Arqos Bridge V2

Usage:
  node tools/bridge_arqos_v2.js [options]

Options:
  --agent=<name>    Process only specific agent (e.g., d2_sentinela)
  --tier=<tier>     Process only specific tier (starter|pro|enterprise)
  --validate-only   Validate specs without generating axioms
  --help, -h        Show this help message

Examples:
  node tools/bridge_arqos_v2.js
  node tools/bridge_arqos_v2.js --agent=d2_sentinela
  node tools/bridge_arqos_v2.js --tier=starter
  node tools/bridge_arqos_v2.js --validate-only
      `);
      process.exit(0);
    }
  }

  return options;
}

// Run if called directly
if (require.main === module) {
  const options = parseArgs();
  const stats = bridge(options);

  // Exit code based on results
  if (stats.failed > 0) {
    process.exit(1);
  }
  process.exit(0);
}

module.exports = { bridge, convertToArqosAxiom, validateAxiom };
