#!/usr/bin/env node

/**
 * KC7 Validation - REAL Implementation
 * 
 * Uses actual D2 Sentinela implementation (not mock!)
 * Processes real KC7 dataset and measures performance.
 * 
 * Usage:
 *   node tools/kc7_validation_real.js
 *   node tools/kc7_validation_real.js --dataset=ransomware
 */

const fs = require('fs');
const path = require('path');

// Import real agent (not mock!)
const { DalionSentinela } = require('../src/agents/d2_sentinela');

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
 * Convert KC7 log format to Sentinela SecurityEvent format
 */
function convertKC7ToSecurityEvent(kc7Log) {
  // KC7 format varies by dataset
  // This is for phishing_intrusion dataset
  
  if (kc7Log.type === 'email') {
    return {
      timestamp: kc7Log.timestamp || new Date().toISOString(),
      event_id: 'email_received',
      log_source_id: 'email_gateway',
      source_ip: kc7Log.sender_ip || '0.0.0.0',
      action: 'email_delivery',
      status: kc7Log.delivered ? 'success' : 'blocked',
      severity: kc7Log.is_malicious ? 'high' : 'informational',
      message: `Email from ${kc7Log.sender} to ${kc7Log.recipient}`,
      email_sender: kc7Log.sender,
      email_recipient: kc7Log.recipient,
      user_agent: kc7Log.user_agent
    };
  }

  if (kc7Log.type === 'network') {
    return {
      timestamp: kc7Log.timestamp || new Date().toISOString(),
      event_id: 'network_connection',
      log_source_id: 'firewall',
      source_ip: kc7Log.source_ip,
      destination_ip: kc7Log.dest_ip,
      source_port: kc7Log.source_port,
      destination_port: kc7Log.dest_port,
      protocol: kc7Log.protocol || 'TCP',
      action: 'network_egress',
      status: kc7Log.allowed ? 'allowed' : 'blocked',
      severity: kc7Log.is_malicious ? 'critical' : 'informational',
      message: `Connection from ${kc7Log.source_ip} to ${kc7Log.dest_ip}:${kc7Log.dest_port}`
    };
  }

  // Generic event
  return {
    timestamp: kc7Log.timestamp || new Date().toISOString(),
    event_id: kc7Log.event_id || 'unknown',
    log_source_id: kc7Log.source || 'unknown',
    source_ip: kc7Log.source_ip || '0.0.0.0',
    action: kc7Log.action || 'unknown',
    status: kc7Log.status || 'unknown',
    severity: kc7Log.severity || 'informational',
    message: kc7Log.message || 'No message'
  };
}

/**
 * Load KC7 dataset
 */
function loadKC7Dataset(datasetName = 'phishing_test') {
  const dataPath = path.join(__dirname, `../data/kc7/${datasetName}.json`);
  
  if (!fs.existsSync(dataPath)) {
    log(`❌ Dataset not found: ${dataPath}`, 'red');
    log('\nAvailable datasets should be in: data/kc7/', 'yellow');
    log('Download from: https://kc7cyber.com/datasets/\n', 'cyan');
    process.exit(1);
  }

  return JSON.parse(fs.readFileSync(dataPath, 'utf8'));
}

/**
 * Main validation function
 */
async function validateWithKC7(options = {}) {
  log('\n🛡️  KC7 Validation - REAL Implementation\n', 'cyan');

  const datasetName = options.dataset || 'phishing_test';
  
  log(`📂 Loading dataset: ${datasetName}`, 'blue');
  const kc7Data = loadKC7Dataset(datasetName);
  
  const totalLogs = kc7Data.logs ? kc7Data.logs.length : 0;
  log(`📊 Total logs: ${totalLogs}\n`, 'blue');

  if (totalLogs === 0) {
    log('❌ No logs found in dataset', 'red');
    process.exit(1);
  }

  // Initialize real agent (NOT MOCK!)
  log('🤖 Initializing D2 Sentinela...', 'blue');
  const sentinela = new DalionSentinela();
  log('✅ Sentinela ready\n', 'green');

  // Statistics
  const stats = {
    total: totalLogs,
    processed: 0,
    anomalies: 0,
    true_positives: 0,
    false_positives: 0,
    false_negatives: 0,
    true_negatives: 0,
    by_risk_level: {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    },
    processing_times: []
  };

  // Process each log
  log('🔍 Processing logs...\n', 'blue');
  
  for (let i = 0; i < kc7Data.logs.length; i++) {
    const kc7Log = kc7Data.logs[i];
    const event = convertKC7ToSecurityEvent(kc7Log);

    // Measure processing time (REAL, not mock!)
    const startTime = performance.now();
    
    try {
      const result = await sentinela.analyze(event);
      
      const endTime = performance.now();
      const processingTime = endTime - startTime;
      stats.processing_times.push(processingTime);

      stats.processed++;

      // Log detection
      if (result.anomaly) {
        stats.anomalies++;
        stats.by_risk_level[result.risk_level]++;

        log(`  [${i + 1}/${totalLogs}] ⚠️  ANOMALY DETECTED`, 'yellow');
        log(`    IP: ${event.source_ip}`, 'yellow');
        log(`    Score: ${result.anomaly_score}`, 'yellow');
        log(`    Risk: ${result.risk_level}`, 'yellow');
        log(`    Reason: ${result.reason}`, 'yellow');
        log(`    Time: ${processingTime.toFixed(2)}ms\n`, 'cyan');

        // Compare with ground truth (if available)
        if ('is_malicious' in kc7Log) {
          if (kc7Log.is_malicious) {
            stats.true_positives++;
          } else {
            stats.false_positives++;
          }
        }
      } else {
        // No anomaly detected
        if ('is_malicious' in kc7Log) {
          if (kc7Log.is_malicious) {
            stats.false_negatives++;
            log(`  [${i + 1}/${totalLogs}] ❌ MISSED: ${event.source_ip}`, 'red');
          } else {
            stats.true_negatives++;
          }
        }
      }

    } catch (error) {
      log(`  [${i + 1}/${totalLogs}] 💥 ERROR: ${error.message}`, 'red');
    }

    // Progress indicator every 10 logs
    if ((i + 1) % 10 === 0 && i > 0) {
      const progress = ((i + 1) / totalLogs * 100).toFixed(0);
      log(`  Progress: ${i + 1}/${totalLogs} (${progress}%)`, 'cyan');
    }
  }

  // Calculate statistics
  const avgTime = stats.processing_times.reduce((a, b) => a + b, 0) / stats.processing_times.length;
  const maxTime = Math.max(...stats.processing_times);
  const minTime = Math.min(...stats.processing_times);

  const hasGroundTruth = stats.true_positives + stats.false_positives + 
                         stats.false_negatives + stats.true_negatives > 0;

  let accuracy = 0;
  let precision = 0;
  let recall = 0;
  let f1Score = 0;
  let falsePositiveRate = 0;

  if (hasGroundTruth) {
    const total = stats.true_positives + stats.false_positives + 
                  stats.false_negatives + stats.true_negatives;
    
    accuracy = (stats.true_positives + stats.true_negatives) / total;
    
    if (stats.true_positives + stats.false_positives > 0) {
      precision = stats.true_positives / (stats.true_positives + stats.false_positives);
    }
    
    if (stats.true_positives + stats.false_negatives > 0) {
      recall = stats.true_positives / (stats.true_positives + stats.false_negatives);
    }
    
    if (precision + recall > 0) {
      f1Score = 2 * (precision * recall) / (precision + recall);
    }

    if (stats.false_positives + stats.true_negatives > 0) {
      falsePositiveRate = stats.false_positives / (stats.false_positives + stats.true_negatives);
    }
  }

  // Print summary
  log('\n' + '='.repeat(60), 'cyan');
  log('📊 VALIDATION SUMMARY', 'cyan');
  log('='.repeat(60), 'cyan');
  
  log('\n📈 Processing Statistics:', 'blue');
  log(`  Total logs processed: ${stats.processed}`, 'cyan');
  log(`  Anomalies detected: ${stats.anomalies} (${(stats.anomalies/stats.processed*100).toFixed(1)}%)`, 'cyan');
  
  log('\n⚡ Performance Metrics:', 'blue');
  log(`  Average time: ${avgTime.toFixed(2)}ms`, 'cyan');
  log(`  Min time: ${minTime.toFixed(2)}ms`, 'cyan');
  log(`  Max time: ${maxTime.toFixed(2)}ms`, 'cyan');
  log(`  Throughput: ${(1000/avgTime).toFixed(0)} events/second`, 'cyan');

  log('\n🎯 Risk Level Distribution:', 'blue');
  log(`  Low: ${stats.by_risk_level.low}`, 'cyan');
  log(`  Medium: ${stats.by_risk_level.medium}`, 'cyan');
  log(`  High: ${stats.by_risk_level.high}`, 'cyan');
  log(`  Critical: ${stats.by_risk_level.critical}`, 'cyan');

  if (hasGroundTruth) {
    log('\n🎯 Accuracy Metrics (vs Ground Truth):', 'blue');
    log(`  True Positives: ${stats.true_positives}`, 'green');
    log(`  True Negatives: ${stats.true_negatives}`, 'green');
    log(`  False Positives: ${stats.false_positives}`, 'red');
    log(`  False Negatives: ${stats.false_negatives}`, 'red');
    log(`  Accuracy: ${(accuracy * 100).toFixed(2)}%`, 'cyan');
    log(`  Precision: ${(precision * 100).toFixed(2)}%`, 'cyan');
    log(`  Recall: ${(recall * 100).toFixed(2)}%`, 'cyan');
    log(`  F1 Score: ${(f1Score * 100).toFixed(2)}%`, 'cyan');
    log(`  False Positive Rate: ${(falsePositiveRate * 100).toFixed(2)}%`, 'cyan');
  }

  log('\n' + '='.repeat(60) + '\n', 'cyan');

  // Final verdict
  if (hasGroundTruth) {
    if (accuracy >= 0.90 && falsePositiveRate < 0.05) {
      log('🎉 EXCELLENT: High accuracy with low false positives!', 'green');
    } else if (accuracy >= 0.75 && falsePositiveRate < 0.10) {
      log('✅ GOOD: Acceptable accuracy and false positive rate', 'green');
    } else if (accuracy >= 0.60) {
      log('⚠️  FAIR: Needs improvement in detection accuracy', 'yellow');
    } else {
      log('❌ POOR: Detection accuracy too low', 'red');
    }
  } else {
    log('ℹ️  No ground truth available - metrics limited', 'blue');
  }

  log('');

  return stats;
}

// Parse arguments
function parseArgs() {
  const args = process.argv.slice(2);
  const options = {};

  for (const arg of args) {
    if (arg.startsWith('--dataset=')) {
      options.dataset = arg.split('=')[1];
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
KC7 Validation - REAL Implementation

Usage:
  node tools/kc7_validation_real.js [options]

Options:
  --dataset=<name>  Specify dataset name (default: phishing_test)
  --help, -h        Show this help message

Examples:
  node tools/kc7_validation_real.js
  node tools/kc7_validation_real.js --dataset=ransomware
      `);
      process.exit(0);
    }
  }

  return options;
}

// Run if called directly
if (require.main === module) {
  const options = parseArgs();
  validateWithKC7(options).catch(error => {
    log(`\n💥 Validation crashed: ${error.message}\n`, 'red');
    console.error(error.stack);
    process.exit(1);
  });
}

module.exports = { validateWithKC7, convertKC7ToSecurityEvent };
