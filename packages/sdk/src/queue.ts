/**
 * A spooled event: its final, canonical-ready request body. The body is
 * fixed at record() time (event_id, occurred_at, redacted payload,
 * payload_hash), so every retry, including after a restart, sends identical
 * bytes and the server's event_id idempotency makes delivery exactly-once.
 */
export interface SpooledEvent {
  event_id: string;
  body: string;
  queued_at: number;
}

/** FIFO store. Implementations must preserve order and dedupe by event_id. */
export interface Spool {
  load(): Promise<number> | number;
  push(e: SpooledEvent): Promise<void> | void;
  peek(): Promise<SpooledEvent | undefined> | SpooledEvent | undefined;
  /** Remove the head, which must have this id. */
  shift(eventId: string): Promise<void> | void;
  size(): Promise<number> | number;
}

export class MemorySpool implements Spool {
  private q: SpooledEvent[] = [];
  private ids = new Set<string>();
  load() {
    return this.q.length;
  }
  push(e: SpooledEvent) {
    if (this.ids.has(e.event_id)) return;
    this.ids.add(e.event_id);
    this.q.push(e);
  }
  peek() {
    return this.q[0];
  }
  shift(id: string) {
    if (this.q[0]?.event_id === id) {
      this.q.shift();
      this.ids.delete(id);
    }
  }
  size() {
    return this.q.length;
  }
}
