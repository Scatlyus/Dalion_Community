import { StrategicDecision, SecurityAction } from '../d12_rottweiler/types';

export interface ResponseAction {
    id: string;
    action: SecurityAction;
    target: string;
    timestamp: string;
    priority: number;
    status: 'pending' | 'executing' | 'completed' | 'failed';
    reason: string;
}

export interface ExecutionResult {
    action_id: string;
    success: boolean;
    details: string;
    timestamp: string;
}

export interface D1Config {
    auto_execute: boolean;
    require_approval_for: SecurityAction[];
    logging_level: 'verbose' | 'silent';
}
