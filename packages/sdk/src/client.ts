import { normalizeTimestamp, type EventInput, type SealedRecord } from "@audittrail/core";
import { MemoryQueueStore, type QueueStore, type QueuedEvent } from "./queue.js";

export interface AuditTrailOptions {
  /** Tenant API key (at_…). */
  apiKey: string;
  /** Ingestion API base URL. Default http://localhost:8080 */
  baseUrl?: string;
  /** Default agent_id when an event doesn't set one. */
  agentId?: string;
  /** Where queued events live until acknowledged. Default: in memory. Use FileQueueStore (from "@audittrail/sdk/node") to survive restarts. */
  store?: QueueStore;
  /** Retry backoff for network errors / 5xx / 429. */
  retry?: { baseDelayMs?: number; maxDelayMs?: number };
  /** Per-request timeout. Default 15s. */
  timeoutMs?: number;
  /** Max queued events before record() rejects (backpressure). Default 100k. */
  maxQueue?: number;
  /** Called for events the server permanently rejected (4xx), and for transient errors while retrying. */
  onError?: (err: AuditTrailError, event?: QueuedEvent) => void;
  fetch?: typeof fetch;
}

export class AuditTrailError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
    readonly code: string,
    readonly permanent: boolean,
    readonly body?: unknown,
  ) {
    super(message);
    this.name = "AuditTrailError";
  }
}

type Waiter = { resolve: (r: SealedRecord) => void; reject: (e: unknown) => void };

function uuid(): string {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c?.randomUUID) return c.randomUUID();
  const b = new Uint8Array(16);
  c!.getRandomValues(b);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * AuditTrail client.
 *
 * The server owns the hash chain: this client never computes or stores
 * `previous_hash`. Each event gets its `id` (idempotency key) and
 * `timestamp` at the moment `record()` is called, is appended to a local
 * queue, and is delivered strictly in order by a single sender. Transient
 * failures (network down, 5xx, 429) retry the head of the queue with
 * backoff — never skipping ahead — so a dropped connection delays events but
 * never drops or reorders them. Because the id is fixed, a retry of a request
 * the server already committed returns the original sealed record instead of
 * a duplicate.
 */
export class AuditTrail {
  readonly baseUrl: string;
  private readonly opts: AuditTrailOptions;
  private readonly store: QueueStore;
  private readonly fetchImpl: typeof fetch;
  private readonly waiters = new Map<string, Waiter>();
  private draining: Promise<void> | null = null;
  private closed = false;
  private idleResolvers: (() => void)[] = [];
  private ready: Promise<void>;

  constructor(opts: AuditTrailOptions) {
    if (!opts.apiKey) throw new Error("AuditTrail: apiKey is required");
    this.opts = opts;
    this.baseUrl = (opts.baseUrl ?? "http://localhost:8080").replace(/\/+$/, "");
    this.store = opts.store ?? new MemoryQueueStore();
    const f = opts.fetch ?? (globalThis as { fetch?: typeof fetch }).fetch;
    if (!f) throw new Error("AuditTrail: global fetch not available; pass options.fetch");
    this.fetchImpl = f.bind(globalThis);
    // Events persisted by a previous process are delivered first.
    this.ready = Promise.resolve(this.store.load()).then((n) => {
      if (n > 0) this.kick();
    });
  }

  /**
   * Record an event and wait until it is sealed into the ledger.
   * Resolves with the sealed record (hash, previous_hash, signature…).
   */
  async record(event: Omit<EventInput, "agent_id"> & { agent_id?: string }): Promise<SealedRecord> {
    const q = await this.enqueue(event);
    return new Promise<SealedRecord>((resolve, reject) => {
      this.waiters.set(q.id, { resolve, reject });
      this.kick();
    });
  }

  /** Fire-and-forget: queue the event and return its id immediately. */
  track(event: Omit<EventInput, "agent_id"> & { agent_id?: string }): string {
    const id = event.id ?? uuid();
    void this.enqueue({ ...event, id }).then(() => this.kick(), (e) => this.opts.onError?.(e as AuditTrailError));
    return id;
  }

  /** Resolves once every queued event has been delivered (or permanently rejected). */
  async flush(): Promise<void> {
    await this.ready;
    if ((await this.store.size()) === 0 && !this.draining) return;
    this.kick();
    await new Promise<void>((r) => this.idleResolvers.push(r));
  }

  /** Number of events not yet acknowledged by the server. */
  async pending(): Promise<number> {
    return this.store.size();
  }

  async close(): Promise<void> {
    await this.flush();
    this.closed = true;
  }

  private async enqueue(event: Omit<EventInput, "agent_id"> & { agent_id?: string }): Promise<QueuedEvent> {
    if (this.closed) throw new AuditTrailError("client closed", null, "closed", true);
    await this.ready;
    if ((await this.store.size()) >= (this.opts.maxQueue ?? 100_000)) {
      throw new AuditTrailError("local audit queue full", null, "queue_full", false);
    }
    const agent = event.agent_id ?? this.opts.agentId;
    if (!agent) throw new AuditTrailError("agent_id is required (set it per event or via options.agentId)", null, "validation_failed", true);
    const q: QueuedEvent = {
      ...event,
      agent_id: agent,
      id: event.id ?? uuid(),
      timestamp: normalizeTimestamp(event.timestamp ?? new Date()),
    } as QueuedEvent;
    await this.store.push(q);
    return q;
  }

  private kick(): void {
    if (this.draining) return;
    this.draining = this.drain().finally(() => {
      this.draining = null;
      void Promise.resolve(this.store.size()).then((n) => {
        if (n > 0) this.kick();
        else {
          const rs = this.idleResolvers.splice(0);
          rs.forEach((r) => r());
        }
      });
    });
  }

  private async drain(): Promise<void> {
    let attempt = 0;
    for (;;) {
      const head = await this.store.peek();
      if (!head) return;
      try {
        const rec = await this.send(head);
        await this.store.shift(head.id);
        attempt = 0;
        this.settle(head.id, (w) => w.resolve(rec));
      } catch (e) {
        const err = e instanceof AuditTrailError ? e : new AuditTrailError(String((e as Error)?.message ?? e), null, "network_error", false);
        if (err.permanent) {
          // The server will never accept this event; don't block the queue.
          await this.store.shift(head.id);
          this.opts.onError?.(err, head);
          this.settle(head.id, (w) => w.reject(err));
          continue;
        }
        this.opts.onError?.(err, head);
        const base = this.opts.retry?.baseDelayMs ?? 250;
        const max = this.opts.retry?.maxDelayMs ?? 30_000;
        const delay = Math.min(max, base * 2 ** Math.min(attempt, 16)) * (0.5 + Math.random() / 2);
        attempt++;
        await sleep(delay);
      }
    }
  }

  private settle(id: string, fn: (w: Waiter) => void): void {
    const w = this.waiters.get(id);
    if (w) {
      this.waiters.delete(id);
      fn(w);
    }
  }

  private async send(ev: QueuedEvent): Promise<SealedRecord> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.opts.timeoutMs ?? 15_000);
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/v1/events`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${this.opts.apiKey}` },
        body: JSON.stringify(ev),
        signal: ctrl.signal,
      });
    } catch (e) {
      throw new AuditTrailError(`network error: ${(e as Error)?.message ?? e}`, null, "network_error", false);
    } finally {
      clearTimeout(timer);
    }
    const text = await res.text().catch(() => "");
    let body: unknown = undefined;
    try {
      body = text ? JSON.parse(text) : undefined;
    } catch {
      /* non-JSON */
    }
    if (res.status === 200 || res.status === 201) return body as SealedRecord;
    const errInfo = (body as { error?: { code?: string; message?: string } } | undefined)?.error;
    const code = errInfo?.code ?? `http_${res.status}`;
    const transient = res.status >= 500 || res.status === 429 || res.status === 408;
    throw new AuditTrailError(errInfo?.message ?? `HTTP ${res.status}`, res.status, code, !transient, body);
  }
}
