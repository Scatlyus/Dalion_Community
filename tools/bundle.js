const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
// Note: In this environment, we may not have 'adm-zip'. 
// We will simulate bundling by creating a manifest.json and a list of files.
// In a real scenario, we'd use 'archiver' or 'adm-zip'.

const PACKS_BASE = 'c:/root/Dalion/packs';
const DIST_BASE = 'c:/root/Dalion/dist';

function generateHash(content) {
    return crypto.createHash('sha256').update(content).digest('hex');
}

function bundle(tier) {
    const packDir = path.join(PACKS_BASE, tier);
    if (!fs.existsSync(packDir)) return;

    console.log(`Bundling ${tier}...`);
    const manifest = {
        pack_name: `Neuroflux ${tier.charAt(0).toUpperCase() + tier.slice(1)}`,
        tier: tier,
        version: fs.readFileSync('c:/root/Dalion/VERSION', 'utf8').trim(),
        build_date: new Date().toISOString(),
        files: []
    };

    function walk(dir) {
        const files = fs.readdirSync(dir);
        files.forEach(file => {
            const fullPath = path.join(dir, file);
            if (fs.lstatSync(fullPath).isDirectory()) {
                walk(fullPath);
            } else {
                const relativePath = path.relative(packDir, fullPath);
                const content = fs.readFileSync(fullPath);
                manifest.files.push({
                    path: relativePath,
                    hash: generateHash(content),
                    size: content.length
                });
            }
        });
    }

    walk(packDir);

    const distDir = path.join(DIST_BASE, tier);
    if (!fs.existsSync(distDir)) fs.mkdirSync(distDir, { recursive: true });

    fs.writeFileSync(path.join(distDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

    // Simulating ZIP by creating a summary file
    const zipSummary = `neuroflux-${tier}-${manifest.version}.zip simulation\nContains ${manifest.files.length} files.`;
    fs.writeFileSync(path.join(DIST_BASE, `neuroflux-${tier}-${manifest.version}.zip.txt`), zipSummary);

    console.log(`Bundle ${tier} generated in dist/`);
}

['starter', 'pro', 'enterprise'].forEach(tier => bundle(tier));
