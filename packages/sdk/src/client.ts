import { v2 } from "@audittrail/core";
import { redactString, redactValue, DEFAULT_SECRET_PATTERNS, type RedactionOptions, type RedactionReport } from "./redact.js";
import { MemorySpool, type Spool, type SpooledEvent } from "./queue.js";

export type Outcome = "allowed" | "denied" | "error";

/** What the application records (spec_version 2). */
export interface AuditEvent {
  action: string;
  resource: string;
  outcome: Outcome;
  /** The human (or service) on whose behalf this ran. null = autonomous. */
  principal?: { id: string; type: "human" | "service" } | null;
  /** Overrides options.agent for this event. */
  agent?: { id: string; version?: string };
  model?: { id: string; version?: string | null; provider?: string | null } | null;
  delegation?: { type: string; id: string; [k: string]: string | number | boolean | null }[];
  payload?: Record<string, unknown> | null;
  /** Personal data to be encrypted server-side under the subject's key (crypto-shreddable). */
  pii?: { subject: string; fields: Record<string, string> } | null;
  occurredAt?: Date | string;
  /** Supply your own UUIDv7 to make an event idempotent across processes. */
  eventId?: string;
}

export interface Receipt {
  spec_version: "2";
  event_id: string;
  tenant_id: string;
  seq: number;
  occurred_at: string;
  received_at: string;
  prev_hash: string;
  hash: string;
  receipt_signature: string;
  key_id: string;
}

export type Metric =
  | { name: "queued"; eventId: string }
  | { name: "delivered"; eventId: string; replay: boolean; latencyMs: number }
  | { name: "retry"; eventId: string; attempt: number; reason: string }
  | { name: "rejected"; eventId: string; code: string }
  | { name: "redacted"; eventId: string; count: number; kinds: string[] }
  | { name: "spool_size"; value: number };

export interface AuditTrailOptions {
  /** v2 API key (at2_…). Used for the bearer token and to derive the request-signing key. */
  apiKey: string;
  baseUrl?: string;
  /** Default acting agent. */
  agent: { id: string; version?: string };
  /** "open" (default): never throw into the host app. "closed": record()/track() throw if the event can't be queued or is rejected. */
  failMode?: "open" | "closed";
  /** Default: in memory. Use FileSpool from "@audittrail/sdk/node" to survive restarts and long outages. */
  spool?: Spool;
  /** Secret/PII redaction before hashing. Default: built-in secret patterns. false disables. */
  redact?: RedactionOptions | false;
  retry?: { baseDelayMs?: number; maxDelayMs?: number; authPauseMs?: number };
  timeoutMs?: number;
  maxSpool?: number;
  onError?: (err: AuditTrailError) => void;
  onMetric?: (m: Metric) => void;
  fetch?: typeof fetch;
}

export class AuditTrailError extends Error {
  constructor(message: string, readonly status: number | null, readonly code: string, readonly permanent: boolean, readonly eventId?: string) {
    super(message);
    this.name = "AuditTrailError";
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const enc = new TextEncoder();

function nonce(): string {
  const b = new Uint8Array(18);
  (globalThis as { crypto: Crypto }).crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

type Waiter = { resolve: (r: Receipt | null) => void; reject: (e: unknown) => void };

/**
 * AuditTrail v2 client.
 *
 * - The server is the only sequencer. The client computes payload_hash,
 *   fixes event_id (UUIDv7) and occurred_at, and signs each request
 *   (Ed25519 key derived from the API key; fresh timestamp + nonce per
 *   attempt).
 * - Delivery is at-least-once with idempotency, so each event takes effect
 *   exactly once. A single sender drains the spool FIFO with exponential
 *   backoff and full jitter; events are never reordered or skipped.
 * - Fail-open by default: nothing throws into the host application.
 *   Failures go to onError/onMetric and stay spooled.
 */
export class AuditTrail {
  readonly baseUrl: string;
  private readonly o: AuditTrailOptions;
  private readonly spool: Spool;
  private readonly fetchImpl: typeof fetch;
  private readonly waiters = new Map<string, Waiter[]>();
  private readonly signing: ReturnType<typeof v2.signingKeyFromApiKey>;
  private draining: Promise<void> | null = null;
  private idle: (() => void)[] = [];
  /** track() calls still building/spooling their event (flush must wait for them). */
  private inflight = new Set<Promise<unknown>>();
  private ready: Promise<void>;
  private closed = false;

  constructor(opts: AuditTrailOptions) {
    if (!/^at2_[0-9a-f]{12}_/.test(opts.apiKey ?? "")) throw new Error("AuditTrail: a v2 API key (at2_…) is required");
    if (!opts.agent?.id) throw new Error("AuditTrail: options.agent.id is required");
    this.o = opts;
    this.baseUrl = (opts.baseUrl ?? "http://localhost:8080").replace(/\/+$/, "");
    this.spool = opts.spool ?? new MemorySpool();
    const f = opts.fetch ?? (globalThis as { fetch?: typeof fetch }).fetch;
    if (!f) throw new Error("AuditTrail: global fetch not available; pass options.fetch");
    this.fetchImpl = f.bind(globalThis);
    this.signing = v2.signingKeyFromApiKey(opts.apiKey);
    this.ready = Promise.resolve(this.spool.load()).then((n) => {
      if (n > 0) this.kick();
    });
  }

  private get open() {
    return (this.o.failMode ?? "open") === "open";
  }

  private fail(err: AuditTrailError): null {
    try {
      this.o.onError?.(err);
    } catch {
      /* never let a callback break the host */
    }
    if (!this.open) throw err;
    return null;
  }

  private metric(m: Metric) {
    try {
      this.o.onMetric?.(m);
    } catch {
      /* ignore */
    }
  }

  /** Build the exact request body (redaction → canonical checks → payload_hash). */
  async build(ev: AuditEvent): Promise<SpooledEvent> {
    const rep: RedactionReport = { redacted: 0, kinds: new Set() };
    const ro = this.o.redact === false ? null : (this.o.redact ?? {});
    const patterns = ro ? (ro.replaceDefaults ? (ro.patterns ?? []) : [...DEFAULT_SECRET_PATTERNS, ...(ro.patterns ?? [])]) : [];
    let payload = ev.payload ?? null;
    if (payload && ro) {
      payload = redactValue(payload, ro, rep) as Record<string, unknown>;
      if (ro.custom) payload = ro.custom(payload);
    }
    const resource = ro ? redactString(ev.resource, patterns, rep) : ev.resource;
    const eventId = ev.eventId ?? v2.uuidv7();
    const occurred = ev.occurredAt instanceof Date ? ev.occurredAt.toISOString() : (ev.occurredAt ?? new Date().toISOString());
    const pv = v2.fromJS(payload);
    const body: Record<string, unknown> = {
      spec_version: "2",
      event_id: eventId,
      occurred_at: occurred,
      agent: ev.agent ?? this.o.agent,
      principal: ev.principal ?? null,
      model: ev.model ?? null,
      delegation: ev.delegation ?? [],
      action: ev.action,
      resource,
      outcome: ev.outcome,
      payload,
      payload_hash: await v2.payloadHash(pv.kind === "null" ? null : pv),
    };
    if (ev.pii) body.pii = ev.pii;
    const text = JSON.stringify(body);
    // Same validator as the server: malformed events fail here, not after a network round trip.
    await v2.validateEnvelopeBytes(enc.encode(text));
    if (rep.redacted > 0) this.metric({ name: "redacted", eventId, count: rep.redacted, kinds: [...rep.kinds] });
    return { event_id: eventId, body: text, queued_at: Date.now() };
  }

  /** Spool order == call order: each enqueue reserves its slot synchronously. */
  private pushChain: Promise<unknown> = Promise.resolve();

  private enqueue(ev: AuditEvent): Promise<SpooledEvent | null> {
    if (this.closed) {
      try {
        return Promise.resolve(this.fail(new AuditTrailError("client closed", null, "closed", true)));
      } catch (e) {
        return Promise.reject(e);
      }
    }
    // Build (hashing, validation) starts now and runs concurrently with
    // other builds; the push below waits for every earlier call first.
    const built = this.build(ev);
    built.catch(() => undefined); // handled below; avoid an unhandled-rejection window
    const result = this.pushChain.then(async () => {
      let s: SpooledEvent;
      try {
        s = await built;
      } catch (e) {
        const ce = e as { status?: number; code?: string; message?: string };
        return this.fail(new AuditTrailError(ce.message ?? String(e), ce.status ?? null, ce.code ?? "invalid_event", true));
      }
      await this.ready;
      if ((await this.spool.size()) >= (this.o.maxSpool ?? 1_000_000)) {
        return this.fail(new AuditTrailError("local audit spool is full", null, "spool_full", false, s.event_id));
      }
      await this.spool.push(s);
      this.metric({ name: "queued", eventId: s.event_id });
      return s;
    });
    this.pushChain = result.catch(() => undefined);
    return result;
  }

  /** Record an event and wait for its sealed receipt. Fail-open: resolves null on failure. */
  async record(ev: AuditEvent): Promise<Receipt | null> {
    const s = await this.enqueue(ev);
    if (!s) return null;
    const p = new Promise<Receipt | null>((resolve, reject) => {
      const ws = this.waiters.get(s.event_id) ?? [];
      ws.push({ resolve, reject });
      this.waiters.set(s.event_id, ws);
    });
    this.kick();
    return p;
  }

  /** Queue an event without waiting. Returns its event_id. */
  track(ev: AuditEvent): string {
    const eventId = ev.eventId ?? v2.uuidv7();
    const p = this.enqueue({ ...ev, eventId }).then(
      (s) => s && this.kick(),
      () => undefined, // failure already reported through onError
    );
    this.inflight.add(p);
    void p.finally(() => this.inflight.delete(p));
    return eventId;
  }

  async flush(): Promise<void> {
    await this.ready;
    // Events handed to track() just before flush() must not be missed.
    while (this.inflight.size) await Promise.allSettled([...this.inflight]);
    if ((await this.spool.size()) === 0 && !this.draining) return;
    this.kick();
    await new Promise<void>((r) => this.idle.push(r));
  }

  async pending(): Promise<number> {
    return this.spool.size();
  }

  async close(): Promise<void> {
    await this.flush();
    this.closed = true;
  }

  private kick(): void {
    if (this.draining) return;
    this.draining = this.drain().finally(() => {
      this.draining = null;
      void Promise.resolve(this.spool.size()).then((n) => {
        this.metric({ name: "spool_size", value: n });
        if (n > 0 && !this.closed) this.kick();
        else this.idle.splice(0).forEach((r) => r());
      });
    });
  }

  private settle(id: string, fn: (w: Waiter) => void) {
    const ws = this.waiters.get(id);
    if (ws) {
      this.waiters.delete(id);
      ws.forEach(fn);
    }
  }

  private async drain(): Promise<void> {
    let attempt = 0;
    for (;;) {
      const head = await this.spool.peek();
      if (!head) return;
      const started = Date.now();
      let res: { status: number; body: unknown } | null = null;
      let reason = "";
      try {
        res = await this.send(head);
      } catch (e) {
        reason = `network: ${(e as Error).message ?? e}`;
      }
      if (res && (res.status === 202 || res.status === 200)) {
        await this.spool.shift(head.event_id);
        attempt = 0;
        this.metric({ name: "delivered", eventId: head.event_id, replay: res.status === 200, latencyMs: Date.now() - started });
        this.settle(head.event_id, (w) => w.resolve(res!.body as Receipt));
        continue;
      }
      if (res && [400, 409, 413, 422].includes(res.status)) {
        // The server will never accept these bytes: drop, report, keep the queue moving.
        const code = (res.body as { error?: { code?: string } })?.error?.code ?? `http_${res.status}`;
        await this.spool.shift(head.event_id);
        this.metric({ name: "rejected", eventId: head.event_id, code });
        const err = new AuditTrailError(`event rejected: ${code}`, res.status, code, true, head.event_id);
        try {
          this.o.onError?.(err);
        } catch {
          /* ignore */
        }
        this.settle(head.event_id, (w) => (this.open ? w.resolve(null) : w.reject(err)));
        continue;
      }
      // Transient (network, 5xx, 429) or auth (401/403: key revoked or clock
      // skew). Audit events are never silently dropped: they stay spooled and
      // are retried; auth failures back off longer.
      if (res) reason = `http ${res.status}`;
      attempt++;
      this.metric({ name: "retry", eventId: head.event_id, attempt, reason });
      if (res && (res.status === 401 || res.status === 403)) {
        try {
          this.o.onError?.(new AuditTrailError(`authentication failed (${res.status}); events stay spooled`, res.status, "auth", false, head.event_id));
        } catch {
          /* ignore */
        }
        await sleep(this.o.retry?.authPauseMs ?? 60_000);
        continue;
      }
      const base = this.o.retry?.baseDelayMs ?? 250;
      const max = this.o.retry?.maxDelayMs ?? 30_000;
      await sleep(Math.random() * Math.min(max, base * 2 ** Math.min(attempt, 20)));
    }
  }

  private async send(s: SpooledEvent): Promise<{ status: number; body: unknown }> {
    const path = "/v2/events";
    const ts = String(Date.now());
    const n = nonce();
    const bytes = enc.encode(s.body);
    const { privateKey } = await this.signing;
    const msg = await v2.requestMessage("POST", path, ts, n, bytes);
    const sig = new Uint8Array(await (globalThis as { crypto: Crypto }).crypto.subtle.sign({ name: "Ed25519" }, privateKey, enc.encode(msg) as BufferSource));
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.o.timeoutMs ?? 15_000);
    try {
      const res = await this.fetchImpl(this.baseUrl + path, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${this.o.apiKey}`,
          "x-at-timestamp": ts,
          "x-at-nonce": n,
          "x-at-signature": btoa(String.fromCharCode(...sig)),
        },
        body: s.body,
        signal: ctrl.signal,
      });
      const text = await res.text().catch(() => "");
      let body: unknown;
      try {
        body = text ? JSON.parse(text) : undefined;
      } catch {
        body = undefined;
      }
      return { status: res.status, body };
    } finally {
      clearTimeout(timer);
    }
  }
}
