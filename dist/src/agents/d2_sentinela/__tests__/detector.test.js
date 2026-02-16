"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("../index");
describe('DalionSentinela', () => {
    let sentinela;
    beforeEach(() => {
        sentinela = new index_1.DalionSentinela();
    });
    describe('Regra: Burst de Logins (failed_logins_burst)', () => {
        it('deve disparar anomalia após o 3º falha consecutiva do mesmo IP', async () => {
            const event = {
                timestamp: new Date().toISOString(),
                event_id: 'login_fail',
                log_source_id: 'win_sec',
                source_ip: '10.0.0.1',
                action: 'login',
                status: 'failure',
                severity: 'medium',
                message: 'failed'
            };
            await sentinela.analyze(event);
            await sentinela.analyze(event);
            const result = await sentinela.analyze(event);
            expect(result.anomaly).toBe(true);
            expect(result.tags).toContain('failed_logins_burst');
        });
    });
    describe('Regra: IoC Malicioso (known_malicious_ioc)', () => {
        it('deve identificar IP malicioso conhecido', async () => {
            const result = await sentinela.analyze({
                timestamp: new Date().toISOString(),
                event_id: 'conn',
                log_source_id: 'fw',
                source_ip: '185.123.45.67', // Na blacklist
                action: 'connect',
                status: 'success',
                severity: 'high',
                message: 'connected'
            });
            expect(result.anomaly).toBe(true);
            expect(result.anomaly_score).toBeGreaterThanOrEqual(95);
        });
        it('deve identificar domínio de phishing no sender', async () => {
            const result = await sentinela.analyze({
                timestamp: new Date().toISOString(),
                event_id: 'mail',
                log_source_id: 'o365',
                source_ip: '1.2.3.4',
                action: 'receive',
                status: 'success',
                severity: 'critical',
                message: 'phishing',
                email_sender: 'attacker@paypal-secure-login.com'
            });
            expect(result.anomaly).toBe(true);
            expect(result.tags).toContain('known_malicious_ioc');
        });
    });
    describe('Regra: Arquivo Suspeito (unusual_file_activity)', () => {
        it('deve detectar executável escrito em pasta temporária', async () => {
            const result = await sentinela.analyze({
                timestamp: new Date().toISOString(),
                event_id: 'file',
                log_source_id: 'edr',
                source_ip: '10.0.0.5',
                action: 'write',
                status: 'success',
                severity: 'high',
                message: 'writing file',
                file_path: 'C:\\Windows\\Temp\\malware.exe'
            });
            expect(result.anomaly).toBe(true);
            expect(result.tags).toContain('unusual_file_activity');
        });
    });
    describe('Regra: Termos Sensíveis (sensitive_terms_in_message)', () => {
        it('deve capturar palavras-chave de ameaça na mensagem', async () => {
            const result = await sentinela.analyze({
                timestamp: new Date().toISOString(),
                event_id: 'cmd',
                log_source_id: 'sysmon',
                source_ip: '10.0.0.5',
                action: 'exec',
                status: 'success',
                severity: 'medium',
                message: 'detected ransomware attempt on disk'
            });
            expect(result.anomaly).toBe(true);
            expect(result.tags).toContain('sensitive_terms_in_message');
        });
    });
});
