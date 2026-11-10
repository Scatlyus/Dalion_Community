import { SecurityEvent } from '../../agents/d2_sentinela/types';
import { IOC } from '../../agents/d3_espionagem/types';

/**
 * IoCExtractor - Especialista em extração multi-dimensional de indicadores.
 *
 * Capaz de vasculhar o metadata bruto (Suricata EVE) para encontrar
 * domínios em queries DNS, URLs em logs HTTP e hashes JA3 em TLS.
 */
export class IoCExtractor {
    /**
     * Extrai todos os IoCs relevantes de um evento.
     */
    extractFromEvent(event: SecurityEvent): IOC[] {
        const iocs: IOC[] = [];

        // 1. IP de Origem (Sempre presente)
        iocs.push({
            ioc_type: 'IP',
            ioc_value: event.source_ip,
            is_anomaly: false, // Será preenchido pelo orquestrador com base no D2
            event
        });

        const metadata = event.metadata;
        if (!metadata) return iocs;

        // 2. Domínios (DNS)
        const dnsQuery = metadata.dns?.query?.[0] || metadata.dns;
        if (dnsQuery?.rrname) {
            iocs.push({
                ioc_type: 'domain',
                ioc_value: dnsQuery.rrname,
                is_anomaly: false,
                event
            });
        }

        // 3. URL/Hostname (HTTP)
        if (metadata.http?.hostname) {
            iocs.push({
                ioc_type: 'domain',
                ioc_value: metadata.http.hostname,
                is_anomaly: false,
                event
            });
        }

        if (metadata.http?.url) {
            iocs.push({
                ioc_type: 'url',
                ioc_value: metadata.http.url,
                is_anomaly: false,
                event
            });
        }

        // 4. JA3 Hash (TLS)
        if (metadata.tls?.ja3) {
            iocs.push({
                ioc_type: 'hash',
                ioc_value: metadata.tls.ja3,
                is_anomaly: false,
                event
            });
        }

        // 5. Destination IP (C2 potential)
        if (event.destination_ip && event.destination_ip !== '0.0.0.0') {
            iocs.push({
                ioc_type: 'IP',
                ioc_value: event.destination_ip,
                is_anomaly: false,
                event
            });
        }

        // Remover duplicatas de valor (ex: IP de destino igual ao de origem em loops estranhos)
        return this.deduplicate(iocs);
    }

    private deduplicate(iocs: IOC[]): IOC[] {
        const seen = new Set<string>();
        return iocs.filter(ioc => {
            const key = `${ioc.ioc_type}:${ioc.ioc_value}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }
}
