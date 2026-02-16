import { IHistoryStore, SecurityEvent } from './types';

export class MemoryHistoryStore implements IHistoryStore {
    private history: Map<string, SecurityEvent[]> = new Map();

    async get(key: string): Promise<SecurityEvent[]> {
        return this.history.get(key) || [];
    }

    async push(key: string, event: SecurityEvent): Promise<void> {
        if (!this.history.has(key)) {
            this.history.set(key, []);
        }
        const list = this.history.get(key)!;
        list.push(event);

        // Keep last 100
        if (list.length > 100) {
            list.shift();
        }

        // TTL Simulation (1 hour)
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        this.history.set(key, list.filter(e => e.timestamp >= oneHourAgo));
    }

    async clear(): Promise<void> {
        this.history.clear();
    }
}
