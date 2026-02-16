export interface SecurityEvent {
    timestamp: string;
    event_id: string;
    log_source_id: string;
    source_ip: string;
    destination_ip?: string;
    action: string;
    status: 'success' | 'failure' | 'blocked' | 'allowed';
    severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
    message: string;
    username?: string;
    user_agent?: string;
    file_path?: string;
    email_sender?: string;
}

export interface IHistoryStore {
    get(key: string): Promise<SecurityEvent[]>;
    push(key: string, event: SecurityEvent): Promise<void>;
    clear(): Promise<void>;
}

export interface DetectionResult {
    anomaly: boolean;
    reason: string;
    anomaly_score: number; // 0-100
    risk_level: 'low' | 'medium' | 'high' | 'critical';
    tags: string[];
    rules_processed?: number;
}

export interface DetectionRule {
    name: string;
    description: string;
    impact_score: number;
    check: (event: SecurityEvent, history: Map<string, SecurityEvent[]>) => Promise<boolean>;
}
