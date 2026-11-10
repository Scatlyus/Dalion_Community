import { EnrichedIOC } from '../../agents/d3_espionagem/types';
import { SecurityEvent } from '../../agents/d2_sentinela/types';

/**
 * DecisionEngine - Inteligência de agregação de contexto.
 *
 * Quando temos múltiplos IoCs (IP, Domínio, URL), este motor decide
 * qual deles representa a maior ameaça ou como combiná-los.
 */
export class DecisionEngine {
    /**
     * Consolida múltiplos contextos enriquecidos em um único "Contexto Mestre"
     * que será enviado para o orquestrador final.
     */
    consolidate(contexts: EnrichedIOC[], event: SecurityEvent): EnrichedIOC {
        if (contexts.length === 0) {
            throw new Error('DecisionEngine: Nenhum contexto fornecido para consolidação.');
        }

        if (contexts.length === 1) return contexts[0];

        // 1. Priorização por Tipo de Evento
        // Se for um alerta DNS, priorizamos o IoC de tipo 'domain'
        const isDnsAlert = event.action === 'dns' || !!event.metadata?.dns || (event.action === 'suricata_alert' && !!event.message?.toLowerCase().includes('dns'));
        const isHttpAlert = event.action === 'http' || !!event.metadata?.http || (event.action === 'suricata_alert' && !!event.message?.toLowerCase().includes('http'));

        let bestContext = contexts[0];
        let maxWeight = -1;

        for (const ctx of contexts) {
            let weight = ctx.threat_score || 0;

            // Bônus de contexto: se o tipo do IoC bate com a natureza da ameaça
            if (isDnsAlert && ctx.ioc_type === 'domain') weight += 20;
            if (isHttpAlert && (ctx.ioc_type === 'url' || ctx.ioc_type === 'domain')) weight += 20;

            // Priorizar domínios e URLs sobre IPs genéricos se eles tiverem qualquer suspeita
            if ((ctx.ioc_type === 'domain' || ctx.ioc_type === 'url') && ctx.threat_score > 50) {
                weight += 10;
            }

            if (weight > maxWeight) {
                maxWeight = weight;
                bestContext = ctx;
            }
        }

        // 2. Mesclagem de Tags
        // Garantimos que as tags de todos os outros contextos sejam agregadas ao melhor contexto
        const allTags = new Set(bestContext.tags || []);
        contexts.forEach(ctx => {
            if (ctx !== bestContext && ctx.tags) {
                ctx.tags.forEach(t => allTags.add(t));
            }
        });

        return {
            ...bestContext,
            threat_score: Math.min(100, Math.max(bestContext.threat_score, ...contexts.map(c => c.threat_score))),
            tags: Array.from(allTags)
        };
    }
}
