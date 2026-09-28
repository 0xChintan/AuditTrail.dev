import type { EventInput } from "@audittrail/core";

/** An event with its id and timestamp fixed at record() time. */
export type QueuedEvent = EventInput & { id: string; timestamp: string };

/**
 * FIFO store for events awaiting acknowledgement. Implementations must keep
 * insertion order and survive whatever failure they claim to survive.
 */
export interface QueueStore {
  /** Load persisted state; returns the number of pending events. */
  load(): Promise<number> | number;
  push(e: QueuedEvent): Promise<void> | void;
  peek(): Promise<QueuedEvent | undefined> | QueuedEvent | undefined;
  /** Remove the head, which must have this id. */
  shift(id: string): Promise<void> | void;
  size(): Promise<number> | number;
}

export class MemoryQueueStore implements QueueStore {
  private q: QueuedEvent[] = [];
  load() {
    return this.q.length;
  }
  push(e: QueuedEvent) {
    this.q.push(e);
  }
  peek() {
    return this.q[0];
  }
  shift(id: string) {
    if (this.q[0]?.id === id) this.q.shift();
  }
  size() {
    return this.q.length;
  }
}
