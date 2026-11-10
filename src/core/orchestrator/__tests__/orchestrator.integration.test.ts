import * as fs from 'fs';
import * as path from 'path';
import { DalionOrchestrator } from '../DalionOrchestrator';
import { DalionSentinela } from '../../../agents/d2_sentinela/index';
import { DalionEspionagem } from '../../../agents/d3_espionagem/index';
import { DalionEthos } from '../../../agents/d10_ethos/index';
import { DalionRottweiler } from '../../../agents/d12_rottweiler/index';
import { SovereignTriad } from '../../triad/SovereignTriad';
import { DalionEventBus } from '../../bus/DalionEventBus';
import { SecurityEvent } from '../../../agents/d2_sentinela/types';
import { ThreatType } from '../../../agents/d10_ethos/types';

// ── Helpers de Mock ───────────────────────────────────────────────────────────

// Mockamos D3 e D10 pois eles possuem dependências externas (Redis, APIs)
// Queremos testar a orquestração e a lógica do D12 com dados reais do sample_eve.json

const makeD3Mock = () => ({
    enrich: jest.fn().mockImplementation(async (request) => {
        const ioc = request.iocs[0];
        const isMalicious = ioc.ioc_value === '45.133.1.25' || ioc.ioc_value === 'evil.com';

        return {
            enriched_iocs: [{
                ...ioc,
                threat_score: isMalicious ? 95 : 10,
                confidence: 0.9,
                reputation: isMalicious ? 'malicious' : 'clean',
                last_enriched: new Date().toISOString()
            }],
            summary_report: {}
        };
    })
});

const makeD10Mock = () => ({
    classify: jest.fn().mockImplementation(async (enriched) => {
        if (enriched.threat_score >= 80) {
            return {
                threat_type: ThreatType.MALWARE,
                mitre_tactics: ['TA0003'],
                confidence: 0.9,
                severity: 'critical',
                recommended_action: 'block'
            };
        }
        return {
            threat_type: ThreatType.CLEAN,
            mitre_tactics: [],
            confidence: 0.9,
            severity: 'low',
            recommended_action: 'allow'
        };
    })
});

// ── Mapeamento EVE → SecurityEvent ───────────────────────────────────────────

function mapEveToSecurityEvent(raw: any, id: number): SecurityEvent {
    const severityMap: Record<number, SecurityEvent['severity']> = {
        1: 'critical',
        2: 'high',
        3: 'medium'
    };

    return {
        timestamp: raw.timestamp,
        event_id: `eve-${id}`,
        log_source_id: 'suricata-sample',
        source_ip: raw.src_ip || '0.0.0.0',
        destination_ip: raw.dest_ip,
        action: raw.event_type === 'alert' ? 'suricata_alert' : (raw.event_type || 'unknown'),
        status: 'allowed',
        severity: raw.alert ? (severityMap[raw.alert.severity] || 'medium') : 'informational',
        message: raw.alert?.signature || `${raw.event_type} event observed`,
        metadata: raw
    };
}

// ── Testes de Integração ──────────────────────────────────────────────────────

describe('DalionOrchestrator Integration (sample_eve.json)', () => {
    let orchestrator: DalionOrchestrator;
    let bus: DalionEventBus;
    let eveLogs: any[];

    beforeAll(() => {
        // Carrega logs reais do sample_eve.json
        const filePath = path.join(process.cwd(), 'sample_eve.json');
        const content = fs.readFileSync(filePath, 'utf-8');
        eveLogs = content.split('\n').filter(l => l.trim()).map(l => JSON.parse(l));

        // Inicializa componentes (reais onde possível, mocks para I/O externo)
        bus = new DalionEventBus();
        const d2 = new DalionSentinela(); // Real
        const d3 = makeD3Mock() as any;    // Mock
        const d10 = makeD10Mock() as any;  // Mock
        const d12 = new DalionRottweiler(); // Real
        const triad = new SovereignTriad(bus); // Real

        orchestrator = new DalionOrchestrator(d2, d3, d10, d12, triad, bus);
    });

    it('deve processar o primeiro log de Trojan Beaconing e decidir por BLOCK ou ISOLATE', async () => {
        const event = mapEveToSecurityEvent(eveLogs[0], 0);
        expect(event.source_ip).toBe('10.0.4.100');
        expect(event.action).toBe('suricata_alert');

        const result = await orchestrator.process(event);

        expect(result.decision).toBeDefined();
        // D12 Rottweiler deve decidir BLOCK ou ISOLATE para Trojan com alert severity 1
        expect(['BLOCK', 'ISOLATE_HOST']).toContain(result.decision.action);
        expect(result.decision.priority).toBeGreaterThanOrEqual(90);
    });

    it('deve processar tráfego DNS normal do Google e decidir por MONITOR ou ALLOW', async () => {
        const event = mapEveToSecurityEvent(eveLogs[1], 1);
        expect(event.metadata.event_type).toBe('dns');

        const result = await orchestrator.process(event);

        expect(['MONITOR', 'ALLOW']).toContain(result.decision.action);
        expect(result.errors).toHaveLength(0);
    });

    it('deve identificar o Ransomware Wannacry e decidir por ISOLATE_HOST com prioridade máxima', async () => {
        const event = mapEveToSecurityEvent(eveLogs[3], 3);
        expect(event.message).toContain('Wannacry');

        const result = await orchestrator.process(event);

        expect(result.decision.action).toBe('ISOLATE_HOST');
        expect(result.decision.priority).toBe(100);
    });

    it('deve emitir eventos no bus durante o processamento do pipeline', async () => {
        const event = mapEveToSecurityEvent(eveLogs[0], 0);
        const eventsFound: string[] = [];

        bus.subscribe('D2_DETECTION', () => { eventsFound.push('D2'); });
        bus.subscribe('D12_DECISION', () => { eventsFound.push('D12'); });

        await orchestrator.process(event);

        expect(eventsFound).toContain('D2');
        expect(eventsFound).toContain('D12');
    });

    it('deve acionar o SovereignTriad Ω para ameaças críticas (Trojan/Wannacry)', async () => {
        // Wannacry log (index 3)
        const event = mapEveToSecurityEvent(eveLogs[3], 3);
        const result = await orchestrator.process(event);

        // Como o D12 decidiu por ISOLATE_HOST e o D3 mockado retorna score 95,
        // o orquestrador deve ter acionado o Triad (threshold 80)
        expect(result.omega_triggered).toBe(true);
    });
});
