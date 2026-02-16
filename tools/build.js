const { execSync } = require('child_process');

console.log("=== Neuroflux Build System Starting ===");

function run(script) {
    console.log(`\n> Running ${script}...`);
    try {
        execSync(`node tools/${script}`, { stdio: 'inherit' });
    } catch (e) {
        console.error(`Error running ${script}`);
        process.exit(1);
    }
}

run('normalize.js');
run('validate.js');
run('bundle.js');

console.log("\n=== Build Completed Successfully! Packages are in dist/ ===");
