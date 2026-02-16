import { EnrichedIOC } from '../d3_espionagem/types';
import { ThreatClassifier } from './classifier';
import { ClassificationResult, D10Config } from './types';

export class DalionEthos {
    private classifier: ThreatClassifier;
    private config: D10Config;

    constructor(config?: Partial<D10Config>) {
        this.classifier = new ThreatClassifier();
        this.config = {
            confidence_threshold: config?.confidence_threshold ?? 0.5,
            auto_escalate_critical: config?.auto_escalate_critical ?? true
        };
    }

    /**
     * Classifies an enriched IOC into a specific threat category
     */
    async classify(enriched: EnrichedIOC): Promise<ClassificationResult> {
        console.log(`   [D10 Debug] Classifying ${enriched.ioc_value} | Tags: [${enriched.tags?.join(', ') || ''}] | Score: ${enriched.threat_score}`);
        console.log(`[D10 Ethos] Classifying signal for ${enriched.ioc_value}...`);

        const result = await this.classifier.classify(enriched);

        // Apply config-based logic
        if (this.config.auto_escalate_critical && result.severity === 'critical') {
            result.confidence = Math.max(result.confidence, 0.9);
        }

        return result;
    }

    /**
     * Batch classification
     */
    async classifyBatch(enrichedList: EnrichedIOC[]): Promise<ClassificationResult[]> {
        return Promise.all(enrichedList.map(item => this.classify(item)));
    }
}

export default DalionEthos;
