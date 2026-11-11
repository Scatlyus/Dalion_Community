/**
 * Type definitions for Dalion D4 Intel Campo
 * Tactical Intelligence & OSINT Agent
 */

export interface TacticalIntel {
    target: string;
    source: string; // Feed name (e.g., 'InternalDiscovery', 'OSINT_Feed_Alpha')
    signals: OSINTSignal[];
    attribution?: AttributionInfo;
    confidence: number; // 0-1
    last_seen: string;
}

export interface OSINTSignal {
    name: string; // e.g., 'known_phishing_campaign', 'actor_linked_infrastructure'
    category: 'campaign' | 'actor' | 'vulnerability' | 'malware_family';
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface AttributionInfo {
    actor_name?: string; // e.g., 'Lazarus', 'APT28', 'RansomCartel'
    country_of_origin?: string;
    motivation?: string;
    aliases?: string[];
}

export interface FieldIntelReport {
    subnet: string;
    event_count: number;
    anomaly_ratio: number;
    top_targets: string[];
    correlation_detected: boolean;
    timestamp: string;
}

export interface IntelCampoConfig {
    min_confidence: number;
    enable_external_feeds: boolean; // Lab: usually false/mocked
}
