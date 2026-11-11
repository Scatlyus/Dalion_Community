import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';

test('generators do not overwrite existing output and KC7 benign sources avoid the malicious host', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dalion-generator-'));
    const outputs = ['sample.json', 'eve.json', 'kc7.json'].map(name => path.join(dir, name));
    const commands = [
        ['gen_sample.js', outputs[0]],
        ['tools/generate_eve_json.js', outputs[1]],
        [require.resolve('ts-node/dist/bin.js'), '--transpile-only', 'tools/generate_kc7_dataset.ts', outputs[2]],
    ];
    try {
        for (const args of commands) {
            const first = spawnSync(process.execPath, args, { encoding: 'utf8' });
            expect(first.status).toBe(0);
            const original = fs.readFileSync(args[args.length - 1], 'utf8');
            const second = spawnSync(process.execPath, args, { encoding: 'utf8' });
            expect(second.status).not.toBe(0);
            expect(fs.readFileSync(args[args.length - 1], 'utf8')).toBe(original);
        }
        const dataset = JSON.parse(fs.readFileSync(outputs[2], 'utf8')) as Array<{ src_ip: string; http?: { hostname: string } }>;
        const benign = dataset.filter(item => ['google.com', 'cloudflare.com', 'youtube.com'].includes(item.http?.hostname || ''));
        expect(benign).toHaveLength(50);
        expect(benign.every(item => item.src_ip !== '10.0.1.50')).toBe(true);
    } finally {
        outputs.filter(file => fs.existsSync(file)).forEach(file => fs.unlinkSync(file));
        fs.rmdirSync(dir);
    }
}, 30000);
