/**
 * Type definitions for Dalion D2 Sentinela
 * Based on spec: Dalion_op_sentinela__Dn-SEC-SNT__Vr 1.4.4
 */

export interface SecurityEvent {
  // Required fields
  timestamp: string; // ISO 8601 format
  event_id: string;
  log_source_id: string;
  source_ip: string;
  action: string;
  status: 'success' | 'failure' | 'blocked' | 'allowed';
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  message: string;

  // Optional fields
  destination_ip?: string;
  source_port?: number;
  destination_port?: number;
  protocol?: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS';
  username?: string;
  device_type?: string;
  url?: string;
  file_path?: string;
  file_hash?: string;
  process_name?: string;
  process_id?: number;
  user_agent?: string;
  email_sender?: string;
  email_recipient?: string;
}

export interface DetectionResult {
  anomaly: boolean;
  reason: string;
  anomaly_score: number; // 0-100
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  tags: string[];
}

export interface DetectionRule {
  name: string;
  description: string;
  impact_score: number;
  check: (
    event: SecurityEvent,
    history: Map<string, SecurityEvent[]>
  ) => Promise<boolean>;
}

export interface RuleStatistics {
  rule: string;
  triggers: number;
  false_positives: number;
  last_triggered: string | null;
}

export interface SentinelaConfig {
  anomaly_threshold?: number; // Default: 60
  history_retention_minutes?: number; // Default: 60
  max_events_per_ip?: number; // Default: 100
  enable_ml_detection?: boolean; // Default: false
}
