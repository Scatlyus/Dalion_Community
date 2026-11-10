import { DalionEvent, EventPayload } from './events';

// Handler tipado — recebe apenas o payload do evento subscrito
export type EventHandler<T extends DalionEvent['type']> = (
    payload: EventPayload<T>
) => void | Promise<void>;

// Retorno de subscribe — chame para cancelar a subscrição
export type Unsubscribe = () => void;
