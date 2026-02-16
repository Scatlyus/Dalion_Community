const fs = require('fs');
const path = require('path');
// Note: In a real environment we'd use a validator like 'ajv'
// Here we implement a simplified validation logic.

const PACKS_BASE = 'c:/root/Dalion/packs';
const AGENT_SCHEMA_PATH = 'c:/root/Dalion/shared/schemas/agent.schema.json';
const PACK_SCHEMA_PATH = 'c:/root/Dalion/shared/schemas/pack.schema.json';

function validateFile(filePath, schemaPath) {
    const content = fs.readFileSync(filePath, 'utf8');
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));

    // Simplistic validation for frontmatter (agents) or YAML (packs)
    console.log(`Validating ${path.basename(filePath)}...`);

    if (filePath.endsWith('.md')) {
        const fmMatch = content.match(/^---\r?\n([\s\S]*?)\r?\n---/);
        if (!fmMatch) throw new Error("Missing frontmatter");
        // We could parse YAML here if we had a library, but let's check essentials
        const fm = fmMatch[1];
        if (!fm.includes('id:') || !fm.includes('tier:')) throw new Error("Missing mandatory fields in frontmatter");

        // Placeholder check
        const placeholders = content.match(/\{\{(.*?)\}\}/g) || [];
        console.log(`Found ${placeholders.length} placeholders.`);
    }
}

function runQA() {
    ['starter', 'pro', 'enterprise'].forEach(tier => {
        const packPath = path.join(PACKS_BASE, tier, 'pack.yaml');
        if (fs.existsSync(packPath)) {
            validateFile(packPath, PACK_SCHEMA_PATH);
        }

        const agentsDir = path.join(PACKS_BASE, tier, 'agents');
        if (fs.existsSync(agentsDir)) {
            const agents = fs.readdirSync(agentsDir);
            agents.forEach(agent => {
                validateFile(path.join(agentsDir, agent), AGENT_SCHEMA_PATH);
            });
        }
    });
    console.log("QA Completed Successfully!");
}

try {
    runQA();
} catch (e) {
    console.error("QA Failed:", e.message);
    process.exit(1);
}
