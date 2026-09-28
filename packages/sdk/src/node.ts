import { appendFileSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { Spool, SpooledEvent } from "./queue.js";

export * from "./index.js";

/**
 * Durable disk spool for Node: an append-only JSONL journal of `push` and
 * `ack` records, fsynced on push. Survives crashes and restarts. Events
 * recorded but not yet acknowledged are re-sent on the next start (identical
 * bytes, so no duplicates). Duplicate event_ids in the journal are ignored.
 */
export class FileSpool implements Spool {
  private q: SpooledEvent[] = [];
  private ids = new Set<string>();
  private acksSinceCompact = 0;

  constructor(readonly path: string, readonly opts: { fsync?: boolean } = {}) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  }

  load(): number {
    this.q = [];
    this.ids.clear();
    if (!existsSync(this.path)) return 0;
    const acked = new Set<string>();
    const pushed: SpooledEvent[] = [];
    for (const line of readFileSync(this.path, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line) as { op: "push"; e: SpooledEvent } | { op: "ack"; id: string };
        if (rec.op === "push") pushed.push(rec.e);
        else acked.add(rec.id);
      } catch {
        // torn final line from a crash mid-write: ignore
      }
    }
    for (const e of pushed) {
      if (acked.has(e.event_id) || this.ids.has(e.event_id)) continue;
      this.ids.add(e.event_id);
      this.q.push(e);
    }
    this.compact();
    return this.q.length;
  }

  private append(line: string) {
    if (this.opts.fsync === false) {
      appendFileSync(this.path, line, { mode: 0o600 });
      return;
    }
    const fd = openSync(this.path, "a", 0o600);
    try {
      appendFileSync(fd, line);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  }

  push(e: SpooledEvent): void {
    if (this.ids.has(e.event_id)) return;
    this.append(JSON.stringify({ op: "push", e }) + "\n");
    this.ids.add(e.event_id);
    this.q.push(e);
  }

  peek(): SpooledEvent | undefined {
    return this.q[0];
  }

  shift(id: string): void {
    if (this.q[0]?.event_id !== id) return;
    this.q.shift();
    this.ids.delete(id);
    appendFileSync(this.path, JSON.stringify({ op: "ack", id }) + "\n");
    if (this.q.length === 0 || ++this.acksSinceCompact > 1000) this.compact();
  }

  size(): number {
    return this.q.length;
  }

  private compact(): void {
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, this.q.map((e) => JSON.stringify({ op: "push", e }) + "\n").join(""), { mode: 0o600 });
    renameSync(tmp, this.path);
    this.acksSinceCompact = 0;
  }
}

/** @deprecated v1 name */
export const FileQueueStore = FileSpool;
