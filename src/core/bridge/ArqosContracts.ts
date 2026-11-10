/** Structural interface for the separately maintained Arqos engine. */
export interface OrchestrationPlan {
    id: string;
    sequence: { tool_name: string; tool_input: Record<string, unknown> }[];
    timeout_budget: number;
}

export interface ArqosPipeline {
    executePlan(plan: OrchestrationPlan): Promise<{
        success: boolean;
        outputs: unknown[];
        errors?: string[];
    }>;
}
