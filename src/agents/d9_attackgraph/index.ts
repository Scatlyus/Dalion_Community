/**
 * Dalion D9 AttackGraph - Predictive Attack Chain Modeling
 *
 * Responsible for building real-time attack graphs and predicting the next moves of an adversary.
 */

import { SecurityEvent } from '../d2_sentinela/types';
import { IAttackGraph, AttackNode, AttackEdge, MITREPhase, PredictionResult } from './types';
import { GraphStore } from './GraphStore';
import { AttackPredictor } from './Predictor';

export class DalionAttackGraph implements IAttackGraph {
    private store: GraphStore;
    private predictor: AttackPredictor;

    constructor() {
        this.store = new GraphStore();
        this.predictor = new AttackPredictor();
    }

    /**
     * Ingests a high-confidence event into the attack graph.
     */
    async addEvent(event: SecurityEvent, phase: MITREPhase, ttp?: string): Promise<void> {
        const nodeId = `${event.source_ip}_${phase}_${ttp || 'none'}_${Date.now()}`;

        const node: AttackNode = {
            id: nodeId,
            event_id: event.event_id,
            timestamp: event.timestamp || new Date().toISOString(),
            source_ip: event.source_ip,
            phase,
            ttp,
            description: event.message,
            observed: true
        };

        this.store.addNode(event.source_ip, node);
    }

    /**
     * Generates predictions for a given source host.
     */
    async getPredictions(sourceIp: string): Promise<PredictionResult> {
        const lastNode = this.store.getLastNode(sourceIp);
        return this.predictor.predict(lastNode);
    }

    /**
     * Exports the current graph for visualization or decision making.
     */
    getGraph(sourceIp: string): { nodes: AttackNode[], edges: AttackEdge[] } {
        return {
            nodes: this.store.getNodes(sourceIp),
            edges: this.store.getEdges(sourceIp)
        };
    }
}

export default DalionAttackGraph;
