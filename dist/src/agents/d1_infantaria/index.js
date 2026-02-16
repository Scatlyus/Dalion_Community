"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DalionInfantaria = void 0;
const providers_1 = require("./providers");
class DalionInfantaria {
    config;
    provider;
    history = [];
    constructor(config, provider) {
        this.config = {
            auto_execute: config?.auto_execute ?? true,
            require_approval_for: config?.require_approval_for || ['ISOLATE_HOST'],
            logging_level: config?.logging_level ?? 'verbose'
        };
        this.provider = provider || new providers_1.MockExecutionProvider();
    }
    /**
     * Responds to a strategic decision by executing technical actions
     */
    async respond(decision, target) {
        const actionId = `act-${Date.now()}`;
        console.log(`[D1 Infantaria] Decision Received: ${decision.action} for ${target}`);
        const action = {
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
        }
        else {
            console.log(`[D1 Infantaria] Action ${decision.action} on ${target} PENDING APPROVAL (Safety Protocol)`);
            return {
                action_id: actionId,
                success: false,
                details: 'Action requires manual approval',
                timestamp: new Date().toISOString()
            };
        }
    }
    async execute(action) {
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
    getHistory() {
        return this.history;
    }
}
exports.DalionInfantaria = DalionInfantaria;
exports.default = DalionInfantaria;
