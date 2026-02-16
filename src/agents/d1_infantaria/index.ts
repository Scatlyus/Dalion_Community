import { StrategicDecision } from '../d12_rottweiler/types';
import { ResponseAction, ExecutionResult, D1Config } from './types';
import { IExecutionProvider, MockExecutionProvider } from './providers';

export class DalionInfantaria {
    private config: D1Config;
    private provider: IExecutionProvider;
    private history: ResponseAction[] = [];

    constructor(config?: Partial<D1Config>, provider?: IExecutionProvider) {
        this.config = {
            auto_execute: config?.auto_execute ?? true,
            require_approval_for: config?.require_approval_for || ['ISOLATE_HOST'],
            logging_level: config?.logging_level ?? 'verbose'
        };
        this.provider = provider || new MockExecutionProvider();
    }

    /**
     * Responds to a strategic decision by executing technical actions
     */
    public async respond(decision: StrategicDecision, target: string): Promise<ExecutionResult> {
        const actionId = `act-${Date.now()}`;
        console.log(`[D1 Infantaria] Decision Received: ${decision.action} for ${target}`);

        const action: ResponseAction = {
            id: actionId,
            action: decision.action,
            target,
            timestamp: new Date().toISOString(),
            priority: decision.priority,
            status: 'pending',
            reason: decision.reason
        };

        this.history.push(action);

        if (this.config.auto_execute && !this.config.require_approval_for.includes(decision.action)) {
            return this.execute(action);
        } else {
            console.log(`[D1 Infantaria] Action ${decision.action} on ${target} PENDING APPROVAL (Safety Protocol)`);
            return {
                action_id: actionId,
                success: false,
                details: 'Action requires manual approval',
                timestamp: new Date().toISOString()
            };
        }
    }

    private async execute(action: ResponseAction): Promise<ExecutionResult> {
        action.status = 'executing';
        console.log(`[D1 Infantaria] EXECUTING: ${action.action} on target ${action.target} using ${this.provider.name}...`);

        const details = await this.provider.execute(action.action, action.target);

        action.status = 'completed';
        console.log(`[D1 Infantaria] ✅ ACTION COMPLETED: ${details}`);

        return {
            action_id: action.id,
            success: true,
            details,
            timestamp: new Date().toISOString()
        };
    }

    public getHistory(): ResponseAction[] {
        return this.history;
    }
}

export default DalionInfantaria;
