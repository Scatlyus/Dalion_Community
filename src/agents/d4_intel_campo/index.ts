/**
 * Dalion D4 Intel Campo - Tactical Intelligence & OSINT Agent
 * 
 * Provides deep context on IOCs using internal and (mocked) external feeds.
 */

import { TacticalIntel, IntelCampoConfig, FieldIntelReport } from './types';
import { SecurityEvent } from '../d2_sentinela/types';
import { isIP } from 'net';

export class DalionIntelCampo {
    private config: IntelCampoConfig;
    private intelMap: Map<string, TacticalIntel>;

    constructor(config?: Partial<IntelCampoConfig>) {
        this.config = {
            min_confidence: config?.min_confidence || 0.6,
            enable_external_feeds: config?.enable_external_feeds || false
        };
        this.intelMap = this.initializeIntel();
    }

    /**
     * Correlaciona eventos por subnet para detectar ataques distribuídos (Field Intelligence)
     */
    public analyzeField(events: SecurityEvent[]): FieldIntelReport | undefined {
        if (events.length === 0) return undefined;

        // Extrai subnet (simplificado para os 3 primeiros octetos)
        const getSubnet = (ip: string) => ip.split('.').slice(0, 3).join('.');
        const subnetMap = new Map<string, SecurityEvent[]>();

        events.forEach(ev => {
            if (isIP(ev.source_ip) !== 4) return;
            const sn = getSubnet(ev.source_ip);
            const list = subnetMap.get(sn) || [];
            list.push(ev);
            subnetMap.set(sn, list);
        });

        // Prefer a correlated subnet over unrelated high-volume traffic.
        let topSubnet = '';
        let maxEvents = 0;
        let hasCorrelation = false;
        subnetMap.forEach((evs, sn) => {
            const correlated = evs.length >= 3 && new Set(evs.map(e => e.source_ip)).size >= 2 && evs.some(e => e.severity === 'high' || e.severity === 'critical');
            if ((correlated && !hasCorrelation) || (correlated === hasCorrelation && evs.length > maxEvents)) {
                maxEvents = evs.length;
                topSubnet = sn;
                hasCorrelation = correlated;
            }
        });

        if (!topSubnet) return undefined;

        const subnetEvents = subnetMap.get(topSubnet) || [];
        const anomalyCount = subnetEvents.filter(e => e.severity === 'high' || e.severity === 'critical').length;
        const targets = [...new Set(subnetEvents.map(e => e.destination_ip!).filter(Boolean))];

        return {
            subnet: topSubnet,
            event_count: maxEvents,
            anomaly_ratio: maxEvents > 0 ? anomalyCount / maxEvents : 0,
            top_targets: targets.slice(0, 3),
            correlation_detected: hasCorrelation,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Enrich a target with tactical intelligence
     */
    public async enrichTactical(target: string): Promise<TacticalIntel | undefined> {
        // Lab Mode: Lookup in internal tactical index
        const intel = this.intelMap.get(target);

        if (intel && intel.confidence >= this.config.min_confidence) {
            return intel;
        }

        return undefined;
    }

    private initializeIntel(): Map<string, TacticalIntel> {
        const index = new Map<string, TacticalIntel>();

        // Scenario 1: Phishing Campaign 
        index.set('malicious-pdf-link.com', {
            target: 'malicious-pdf-link.com',
            source: 'InternalDiscovery',
            confidence: 0.95,
            last_seen: new Date().toISOString(),
            signals: [
                {
                    name: 'invoice_phishing_campaign',
                    category: 'campaign',
                    description: 'Part of the persistent Q3 Invoice Lure campaign',
                    severity: 'critical'
                }
            ],
            attribution: {
                actor_name: 'PhishMaster-G',
                motivation: 'Financial'
            }
        });

        // Scenario 2: Known C2 Node
        index.set('45.133.1.25', {
            target: '45.133.1.25',
            source: 'GlobalBlacklist',
            confidence: 0.9,
            last_seen: new Date().toISOString(),
            signals: [
                {
                    name: 'cobalt_strike_beacon',
                    category: 'malware_family',
                    description: 'Confirmed Cobalt Strike C2 server',
                    severity: 'critical'
                }
            ],
            attribution: {
                actor_name: 'Organized-Crime-022',
                motivation: 'Access Brokerage'
            }
        });

        return index;
    }
}

export default DalionIntelCampo;
