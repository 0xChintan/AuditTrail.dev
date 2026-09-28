import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { QueueStore, QueuedEvent } from "./queue.js";

export * from "./index.js";

/**
 * Durable queue for Node: an append-only JSONL journal of `push` and `ack`
 * records. Survives process crashes and restarts — events recorded but not
 * yet acknowledged are re-sent (same ids, so no duplicates) on next start.
 * The journal is compacted when it has no pending events or grows large.
 */
export class FileQueueStore implements QueueStore {
  private q: QueuedEvent[] = [];
  private acksSinceCompact = 0;

  constructor(readonly path: string) {
    mkdirSync(dirname(path), { recursive: true });
  }

  load(): number {
    this.q = [];
    if (!existsSync(this.path)) return 0;
    const acked = new Set<string>();
    const pushed: QueuedEvent[] = [];
    for (const line of readFileSync(this.path, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line) as { op: "push"; e: QueuedEvent } | { op: "ack"; id: string };
        if (rec.op === "push") pushed.push(rec.e);
        else acked.add(rec.id);
      } catch {
        // A torn final line from a crash mid-write: ignore it.
      }
    }
    this.q = pushed.filter((e) => !acked.has(e.id));
    this.compact();
    return this.q.length;
  }

  push(e: QueuedEvent): void {
    appendFileSync(this.path, JSON.stringify({ op: "push", e }) + "\n");
    this.q.push(e);
  }

  peek(): QueuedEvent | undefined {
    return this.q[0];
  }

  shift(id: string): void {
    if (this.q[0]?.id !== id) return;
    this.q.shift();
    appendFileSync(this.path, JSON.stringify({ op: "ack", id }) + "\n");
    if (this.q.length === 0 || ++this.acksSinceCompact > 1000) this.compact();
  }

  size(): number {
    return this.q.length;
  }

  private compact(): void {
    const tmp = this.path + ".tmp";
    writeFileSync(tmp, this.q.map((e) => JSON.stringify({ op: "push", e }) + "\n").join(""));
    renameSync(tmp, this.path);
    this.acksSinceCompact = 0;
  }
}
