import { DalionEvent } from './events';
import { EventHandler, Unsubscribe } from './types';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyHandler = (payload: any) => void;

/**
 * DalionEventBus — Barramento pub/sub síncrono e tipado.
 *
 * Design intencional: síncrono no MVP para garantir ordenação determinística
 * do pipeline D2→D3→D10→D12. Subscribers são chamados em ordem de subscrição.
 *
 * TODO: Evoluir para modo async com Promise.allSettled() nos subscribers quando
 *       agentes externos (ex: D3 chamando VirusTotal) precisarem de isolamento
 *       de falhas sem bloquear o pipeline principal.
 */
export class DalionEventBus {
    private subscribers = new Map<string, Set<AnyHandler>>();

    /**
     * Publica um evento no barramento.
     * Todos os subscribers do tipo são chamados síncronamente.
     */
    publish(event: DalionEvent): void {
        const handlers = this.subscribers.get(event.type);
        if (!handlers || handlers.size === 0) return;

        // A union é discriminada por event.type — payload está sempre presente
        const payload = (event as { type: string; payload: unknown }).payload;
        for (const handler of handlers) {
            handler(payload);
        }
    }

    /**
     * Subscreve a um tipo de evento específico.
     * Retorna uma função que cancela a subscrição quando chamada.
     */
    subscribe<T extends DalionEvent['type']>(
        type: T,
        handler: EventHandler<T>
    ): Unsubscribe {
        if (!this.subscribers.has(type)) {
            this.subscribers.set(type, new Set());
        }

        const handlers = this.subscribers.get(type)!;
        handlers.add(handler as AnyHandler);

        return () => {
            handlers.delete(handler as AnyHandler);
        };
    }

    /**
     * Remove todos os subscribers de um tipo (útil em testes).
     */
    clear(type?: DalionEvent['type']): void {
        if (type) {
            this.subscribers.delete(type);
        } else {
            this.subscribers.clear();
        }
    }

    /**
     * Retorna a contagem de subscribers de um tipo (diagnóstico).
     */
    subscriberCount(type: DalionEvent['type']): number {
        return this.subscribers.get(type)?.size ?? 0;
    }
}

// Singleton global — use em produção para compartilhar o barramento entre módulos
export const bus = new DalionEventBus();
