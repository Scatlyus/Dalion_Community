const fs = require('fs');
const path = require('path');

const AGENTS_DIR = 'c:/root/Dalion/.agent/agents';
const OUTPUT_BASE = 'c:/root/Dalion/packs';
const TEMPLATE_PATH = 'c:/root/Dalion/shared/templates/agent.template.md';

function normalize() {
    const files = fs.readdirSync(AGENTS_DIR);
    const template = fs.readFileSync(TEMPLATE_PATH, 'utf8');

    files.forEach(file => {
        const filePath = path.join(AGENTS_DIR, file);
        if (fs.lstatSync(filePath).isDirectory()) return;

        console.log(`Processing ${file}...`);
        const content = fs.readFileSync(filePath, 'utf8');
        const ext = path.extname(file).toLowerCase();
        
        // Simple extraction logic
        let name = file.replace(ext, '').replace(/_/g, ' ');
        let id = file.replace(ext, '').toLowerCase().replace(/[^a-z0-9]/g, '_');
        let version = "1.0.0";
        let tier = "starter";
        let needs_review = true;

        // Try to find version and tier in content or name
        if (file.toLowerCase().includes('pro')) tier = 'pro';
        if (file.toLowerCase().includes('enterprise')) tier = 'enterprise';
        
        const versionMatch = file.match(/v?(\d+\.\d+\.\d+)/i) || content.match(/version:\s*["']?(\d+\.\d+\.\d+)["']?/i);
        if (versionMatch) version = versionMatch[1];

        // Format into template
        // This is a simplified version, in a real scenario we'd parse the YAML properly
        let systemPrompt = "Não extraído automaticamente.";
        let developerInstructions = "Não extraído automaticamente.";
        let userTemplate = "Não extraído automaticamente.";

        if (ext === '.yaml' || ext === '.yml') {
            // Very basic heuristic for extraction
            const descMatch = content.match(/description:\s*>([\s\S]*?)(?=\n\w+:|$)/i);
            if (descMatch) systemPrompt = descMatch[1].trim();
        } else {
            systemPrompt = content.substring(0, 1000).trim();
        }

        let output = template
            .replace('{{agent_id}}', id)
            .replace('{{agent_name}}', name)
            .replace('{{version}}', version)
            .replace('{{tier}}', tier)
            .replace('{{system_prompt}}', systemPrompt)
            .replace('{{developer_instructions}}', developerInstructions)
            .replace('{{user_template}}', userTemplate);

        // Add needs_review if tier was auto-assigned as starter
        if (tier === 'starter' && !file.toLowerCase().includes('starter')) {
            output = output.replace('tier: "starter"', `tier: "starter"\nneeds_review: true`);
        }

        const targetDir = path.join(OUTPUT_BASE, tier, 'agents');
        if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

        fs.writeFileSync(path.join(targetDir, `${id}.md`), output);
        console.log(`Saved to ${tier}/agents/${id}.md`);
    });
}

normalize();
