"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryHistoryStore = void 0;
class MemoryHistoryStore {
    history = new Map();
    async get(key) {
        return this.history.get(key) || [];
    }
    async push(key, event) {
        if (!this.history.has(key)) {
            this.history.set(key, []);
        }
        const list = this.history.get(key);
        list.push(event);
        // Keep last 100
        if (list.length > 100) {
            list.shift();
        }
        // TTL Simulation (1 hour)
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        this.history.set(key, list.filter(e => e.timestamp >= oneHourAgo));
    }
    async clear() {
        this.history.clear();
    }
}
exports.MemoryHistoryStore = MemoryHistoryStore;
