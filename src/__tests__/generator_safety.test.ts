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

test('stress generator labels every event and rejects unsafe output or invalid counts', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dalion-stress-'));
    const output = path.join(dir, 'events.jsonl');
    const runner = require.resolve('ts-node/dist/bin.js');
    const run = (count: string, target = output) => spawnSync(process.execPath, [runner, '--transpile-only', 'tools/generate_stress_eve.ts', count, target], { encoding: 'utf8' });
    try {
        expect(run('100').status).toBe(0);
        const content = fs.readFileSync(output, 'utf8');
        const events = content.split('\n').map(line => JSON.parse(line));
        expect(events).toHaveLength(100);
        expect(events.every(event => ['ALLOW', 'MONITOR', 'BLOCK', 'QUARANTINE', 'ISOLATE_HOST'].includes(event._expected?.d12_action))).toBe(true);
        expect(events.filter(event => event._expected.d12_action === 'ALLOW')).toHaveLength(70);
        expect(events.filter(event => event._expected.d12_action === 'MONITOR')).toHaveLength(20);
        expect(events.every(event => !/\s/.test(event.dns?.query?.[0]?.rrname || event.http?.hostname || ''))).toBe(true);
        expect(run('100').status).not.toBe(0);
        expect(fs.readFileSync(output, 'utf8')).toBe(content);
        for (const invalid of ['0', '-1', 'abc', '1.5']) expect(run(invalid).status).not.toBe(0);
        expect(run('1', path.join(dir, 'missing', 'events.jsonl')).status).not.toBe(0);
    } finally {
        if (fs.existsSync(output)) fs.unlinkSync(output);
        fs.rmdirSync(dir);
    }
}, 60000);
