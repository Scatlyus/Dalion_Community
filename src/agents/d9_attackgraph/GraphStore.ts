import { AttackNode, AttackEdge, MITREPhase } from './types';

export class GraphStore {
    private nodes: Map<string, AttackNode[]> = new Map(); // source_ip -> nodes
    private edges: Map<string, AttackEdge[]> = new Map(); // source_ip -> edges

    /**
     * Adiciona um nó ao grafo de um host específico.
     */
    addNode(sourceIp: string, node: AttackNode) {
        if (!this.nodes.has(sourceIp)) {
            this.nodes.set(sourceIp, []);
        }

        // Verifica se já existe um nó idêntico (mesma fase/ID) para evitar duplicatas curtas
        const hostNodes = this.nodes.get(sourceIp)!;
        const exists = hostNodes.some(n => n.event_id === node.event_id && n.phase === node.phase && n.ttp === node.ttp);

        if (!exists) {
            hostNodes.push(node);

            // Se houver nós anteriores, cria uma aresta (transição lógica)
            if (hostNodes.length > 1) {
                const prevNode = hostNodes[hostNodes.length - 2];
                this.addEdge(sourceIp, {
                    fromId: prevNode.id,
                    toId: node.id,
                    probability: 0.8, // Default initial probability for observed transitions
                    description: `Observed transition from ${prevNode.phase} to ${node.phase}`
                });
            }
        }
    }

    private addEdge(sourceIp: string, edge: AttackEdge) {
        if (!this.edges.has(sourceIp)) {
            this.edges.set(sourceIp, []);
        }
        this.edges.get(sourceIp)!.push(edge);
    }

    getNodes(sourceIp: string): AttackNode[] {
        return this.nodes.get(sourceIp) || [];
    }

    getEdges(sourceIp: string): AttackEdge[] {
        return this.edges.get(sourceIp) || [];
    }

    getLastNode(sourceIp: string): AttackNode | undefined {
        const hostNodes = this.getNodes(sourceIp);
        return hostNodes.length > 0 ? hostNodes[hostNodes.length - 1] : undefined;
    }
}
