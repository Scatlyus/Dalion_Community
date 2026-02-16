import { SecurityAction } from '../d12_rottweiler/types';

export interface IExecutionProvider {
    name: string;
    execute(action: SecurityAction, target: string): Promise<string>;
}

export class MockExecutionProvider implements IExecutionProvider {
    public name = 'MockExecutionProvider (Lab Mode)';

    public async execute(action: SecurityAction, target: string): Promise<string> {
        // Simulação de delay técnico real
        await new Promise(resolve => setTimeout(resolve, 50));

        switch (action) {
            case 'BLOCK':
                return `[Simulated] IP/Domain ${target} blocked on peripheral firewalls. Evidence: FirewallEntry#${Math.floor(Math.random() * 10000)}`;
            case 'ISOLATE_HOST':
                return `[Simulated] Host ${target} isolated from the network. Evidence: EDR_Isolation_Token_${Date.now()}`;
            case 'QUARANTINE':
                return `[Simulated] Target ${target} moved to secure vault. Evidence: VAULT_ID_${Math.random().toString(36).substring(7)}`;
            case 'MONITOR':
                return `[Simulated] Active monitoring telemetry increased for ${target}.`;
            default:
                return `[Simulated] Action ${action} performed for ${target}.`;
        }
    }
}
