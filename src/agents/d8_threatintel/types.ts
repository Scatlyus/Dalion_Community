export type IntelSource = 'github_security' | 'otx' | 'phishtank' | 'internal_research';

export interface ThreatIntelSignal {
    source: IntelSource;
    ioc_value: string;
    ioc_type: string;
    confidence: number; // 0-1
    threat_level: 'low' | 'medium' | 'high' | 'critical';
    tags: string[];
    recommended_score_boost?: number; // Adicional ao threat_score (0-100)
    raw_data?: any;
    last_seen: string;
}

export interface D8Config {
    enabled_sources: IntelSource[];
    min_confidence: number;
    auto_refresh_interval_ms: number;
}

export interface IntelHubStatus {
    sources_active: number;
    total_signals_indexed: number;
    last_update: string;
}

export interface ThreatScore {
    average_score: number;
    weighted_score: number;
    confidence: number;
    sources_count: number;
    timestamp: string;
}
