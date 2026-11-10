import type { ArqosPipeline, OrchestrationPlan } from './ArqosContracts';

import { DalionEventBus } from '../bus/DalionEventBus';
import { decisionToArqosPlan, omegaToArqosPlan } from './ArqosAdapter';
import { ArqosToolResult } from '../bus/events';

/**
 * ArqosBridge — Conector entre o pipeline Dalion e o Arqos Engine.
 *
 * Assina eventos do DalionEventBus e os encaminha ao PipelineCore do Arqos
 * como OrchestrationPlans. Quando o Arqos conclui, publica ARQOS_TOOL_RESULT
 * no bus para rastreabilidade.
 *
 * Arquitetura unidirecional intencional: Dalion decide, Arqos executa.
 */
export class ArqosBridge {
    private unsubscribers: (() => void)[] = [];

    constructor(
        private readonly pipeline: ArqosPipeline,
        private readonly bus: DalionEventBus
    ) {
        this.registerSubscriptions();
    }

    // ── Subscrições ───────────────────────────────────────────────────────────

    private registerSubscriptions(): void {
        // D12 → Arqos: enforcement (BLOCK, ISOLATE, QUARANTINE)
        const unsubD12 = this.bus.subscribe('D12_DECISION', async (decision) => {
            // Só aciona o Arqos para ações que requerem enforcement ativo
            if (decision.action === 'MONITOR' || decision.action === 'ALLOW') return;

            if (!decision.target || decision.target.trim().toLowerCase() === 'unknown') {
                this.bus.publish({ type: 'ARQOS_TOOL_RESULT', payload: {
                    tool: 'dalion.enforce', ok: false,
                    error: { code: 'INVALID_TARGET', message: 'Enforcement target is missing' }
                } });
                return;
            }

            const plan = decisionToArqosPlan(decision);
            await this.executePlan(plan, 'D12_DECISION');
        });

        // OMEGA_CONSENSUS → Arqos: auditoria irretratável
        const unsubOmega = this.bus.subscribe('OMEGA_CONSENSUS', async (record) => {
            const plan = omegaToArqosPlan(record);
            await this.executePlan(plan, 'OMEGA_CONSENSUS');
        });

        this.unsubscribers.push(unsubD12, unsubOmega);
    }

    // ── Execução ──────────────────────────────────────────────────────────────

    private async executePlan(
        plan: OrchestrationPlan,
        trigger: string
    ): Promise<void> {
        try {
            const result = await this.pipeline.executePlan(plan);

            const toolResult: ArqosToolResult = {
                tool: plan.sequence[0]?.tool_name ?? 'unknown',
                ok: result.success,
                value: result.outputs,
                error: result.errors?.length
                    ? { code: 'ARQOS_EXECUTION_ERROR', message: result.errors.join('; ') }
                    : undefined,
            };

            this.bus.publish({ type: 'ARQOS_TOOL_RESULT', payload: toolResult });

            if (!result.success) {
                console.warn(`[ArqosBridge] Arqos falhou ao executar plano ${plan.id} (trigger: ${trigger})`);
            }
        } catch (err) {
            // Simulated tool failure ou erro inesperado — log e publica falha no bus
            const message = err instanceof Error ? err.message : String(err);
            console.error(`[ArqosBridge] Erro ao executar plano ${plan.id}:`, message);

            this.bus.publish({
                type: 'ARQOS_TOOL_RESULT',
                payload: {
                    tool: plan.sequence[0]?.tool_name ?? 'unknown',
                    ok: false,
                    error: { code: 'ARQOS_BRIDGE_ERROR', message },
                },
            });
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    /**
     * Remove todas as subscrições do bus.
     * Chamar ao desligar o serviço.
     */
    dispose(): void {
        for (const unsub of this.unsubscribers) unsub();
        this.unsubscribers = [];
    }
}
