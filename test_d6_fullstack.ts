import { DalionDiplomacia } from './src/agents/d6_diplomacia/index';
import { DetectionResult } from './src/agents/d2_sentinela/types';
import { ComplianceValidationResult } from './src/agents/d5_artilharia/types';
import { PredictionResult, MITREPhase } from './src/agents/d9_attackgraph/types';
import { strict as assert } from 'assert';
import { StrategicImpact } from './src/agents/d6_diplomacia/types';

async function testD6FullStack() {
    console.log('🧪 Testing D6 Diplomacia - Full Stack Integration (12/12)');

    const d6 = new DalionDiplomacia();

    // Simulando inputs dos outros agentes (D2, D5, D9)
    const mockDetections: DetectionResult[] = [{
        anomaly: true,
        reason: 'Multiple failed logins detected',
        anomaly_score: 85,
        risk_level: 'high',
        tags: ['brute_force']
    }];

    const mockCompliance: ComplianceValidationResult[] = [{
        compliant: false,
        violations: [{
            id: 'RL-LGPD-001',
            name: 'PII Leak',
            description: 'Email in message',
            framework: 'LGPD' as any,
            severity: 'high',
            check: async () => true,
            remediation: 'Mask email'
        }],
        timestamp: new Date().toISOString(),
        summary: 'Detected 1 violation: RL-LGPD-001'
    }];

    const mockPredictions: PredictionResult[] = [{
        current_phase: MITREPhase.EXECUTION,
        confidence_score: 0.75,
        predicted_next_steps: [{
            phase: MITREPhase.PERSISTENCE,
            probability: 0.75,
            description: 'Establishing persistence'
        }]
    }];

    console.log('\n--- Generating Executive Report ---');
    const report = await d6.generateExecutiveReport(mockDetections, mockCompliance, mockPredictions);
    assert.equal(report.impact, StrategicImpact.HIGH);
    assert.ok(report.summary.includes('75%'));
    assert.ok(report.summary.includes(MITREPhase.PERSISTENCE));
    assert.equal(report.metrics.find(metric => metric.name === 'Regulatory Compliance Rate')?.value, 0);

    console.log(`Report ID: ${report.id}`);
    console.log(`Impact: ${report.impact}`);
    console.log('\nNarrative Output:');
    console.log('------------------------------');
    console.log(report.summary);
    console.log('------------------------------');

    console.log('\nKey Business Metrics:');
    report.metrics.forEach(m => console.log(`- ${m.name}: ${m.value}${m.unit || ''} (${m.trend})`));
}

testD6FullStack().catch(error => { console.error(error); process.exitCode = 1; });
