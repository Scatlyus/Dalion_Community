"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DalionEthos = void 0;
const classifier_1 = require("./classifier");
class DalionEthos {
    classifier;
    config;
    constructor(config) {
        this.classifier = new classifier_1.ThreatClassifier();
        this.config = {
            confidence_threshold: config?.confidence_threshold ?? 0.5,
            auto_escalate_critical: config?.auto_escalate_critical ?? true
        };
    }
    /**
     * Classifies an enriched IOC into a specific threat category
     */
    async classify(enriched) {
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
    async classifyBatch(enrichedList) {
        return Promise.all(enrichedList.map(item => this.classify(item)));
    }
}
exports.DalionEthos = DalionEthos;
exports.default = DalionEthos;
