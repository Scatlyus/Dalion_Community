import { SecurityEvent } from '../../agents/d2_sentinela/types';

/**
 * AX-DLN-004: Stateful Context Isolation
 * Centraliza o estado para permitir detecção de trajetórias sem contaminação.
 */
export interface HostContext {
    host_ip: string;
    first_seen: string;
    last_seen: string;
    event_count: number;
    risk_score_trend: number[]; // Histórico de scores para Cronos
    event_timestamps: string[]; // Timestamps para análise de Jitter (Cronos)
    active_threats: string[];
    metadata: Record<string, any>;
}

export class DalionStateContext {
    private static instance: DalionStateContext;
    private state: Map<string, HostContext> = new Map();
    private readonly TTL_MS = 3600000; // 1h (AX-DLN-003 Compliance)
    private readonly MAX_WINDOW_SIZE = 100;

    private constructor() {
        // Auto-cleanup interval (disable in tests to avoid open handles)
        if (process.env.NODE_ENV !== 'test') {
            setInterval(() => this.cleanup(), 300000);
        }
    }

    public static getInstance(): DalionStateContext {
        if (!DalionStateContext.instance) {
            DalionStateContext.instance = new DalionStateContext();
        }
        return DalionStateContext.instance;
    }

    /**
     * Obtém o contexto de um host (Read-Only para sub-agentes)
     */
    public getHostContext(hostIp: string): Readonly<HostContext> | undefined {
        return this.state.get(hostIp);
    }

    /**
     * Atualiza o estado de forma centralizada (Escrita Única)
     */
    public updateHostState(event: SecurityEvent, riskIncrement: number): void {
        const hostIp = event.source_ip;
        const current = this.state.get(hostIp) || this.initializeHost(hostIp);

        current.last_seen = event.timestamp;
        current.event_count++;
        current.risk_score_trend.push(riskIncrement);
        current.event_timestamps.push(event.timestamp);

        // Keep trend window manageable (Sliding Window)
        if (current.risk_score_trend.length > this.MAX_WINDOW_SIZE) {
            current.risk_score_trend.shift();
            current.event_timestamps.shift();
        }

        this.state.set(hostIp, current);
    }

    private initializeHost(hostIp: string): HostContext {
        return {
            host_ip: hostIp,
            first_seen: new Date().toISOString(),
            last_seen: new Date().toISOString(),
            event_count: 0,
            risk_score_trend: [],
            event_timestamps: [],
            active_threats: [],
            metadata: {}
        };
    }

    /**
     * Housekeeping para evitar vazamento de memória (AX-DLN-003)
     */
    public cleanup(): void {
        const now = Date.now();
        for (const [ip, context] of this.state.entries()) {
            const lastSeen = Date.parse(context.last_seen);
            if (now - lastSeen > this.TTL_MS) {
                this.state.delete(ip);
            }
        }
    }
}
