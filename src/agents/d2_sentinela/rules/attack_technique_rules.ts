import { DetectionRule } from '../types';

/**
 * Attack technique detection rules (MITRE ATT&CK)
 */
export function getAttackTechniqueRules(): Map<string, DetectionRule> {
    const rules = new Map<string, DetectionRule>();

    // Rule 12: Suspicious Process Parent (T1059)
    rules.set('suspicious_process_spawn', {
        name: 'suspicious_process_spawn',
        description: 'Suspicious process spawning from common lures (Office/Browser)',
        impact_score: 95,
        check: async (event) => {
            const context = (event as any).context;
            if (!context || !context.process || !context.parent) return false;
            const shells = ['cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe'];
            const lures = ['winword.exe', 'excel.exe', 'outlook.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe'];
            return shells.includes(context.process.toLowerCase()) && lures.includes(context.parent.toLowerCase());
        }
    });

    // Rule 13: Shadow Copy Deletion (T1490)
    rules.set('shadow_copy_deletion', {
        name: 'shadow_copy_deletion',
        description: 'Attempt to delete volume shadow copies (Ransomware behavior)',
        impact_score: 100,
        check: async (event) => {
            const context = (event as any).context;
            if (!context || !context.command) return false;
            const cmd = context.command.toLowerCase();
            return cmd.includes('vssadmin') && cmd.includes('delete') && cmd.includes('shadows');
        }
    });

    // Rule 14: Registry Persistence (T1547)
    rules.set('registry_persistence', {
        name: 'registry_persistence',
        description: 'Suspicious registry change in persistent Run keys',
        impact_score: 85,
        check: async (event) => {
            const context = (event as any).context;
            if (event.action !== 'registry_change' || !context || !context.key) return false;
            return context.key.includes('Run\\') || context.key.includes('RunOnce\\');
        }
    });

    // Rule 15: Ransomware Behavior (Pattern/Rate)
    rules.set('ransomware_behavior', {
        name: 'ransomware_behavior',
        description: 'Detected high-frequency file encryption behavior',
        impact_score: 100,
        check: async (event) => {
            const context = (event as any).context || {};
            return context.pattern === 'encrypt_many_files' || (context.rate_per_min || 0) > 50;
        }
    });

    // Rule 21: Browser to Shell (T1059)
    rules.set('browser_to_shell', {
        name: 'browser_to_shell',
        description: 'Browser process spawned a command shell',
        impact_score: 95,
        check: async (event) => {
            const context = (event as any).context || {};
            if (!context.process || !context.parent) return false;
            const browsers = ['chrome.exe', 'msedge.exe', 'firefox.exe'];
            const shells = ['cmd.exe', 'powershell.exe', 'pwsh.exe'];
            return browsers.includes(context.parent.toLowerCase()) && shells.includes(context.process.toLowerCase());
        }
    });

    return rules;
}
