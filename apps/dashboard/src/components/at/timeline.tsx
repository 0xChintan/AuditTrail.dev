"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { BotIcon, LoaderIcon, RadioIcon, UserIcon } from "lucide-react";
import type { SealedRecord } from "@audittrail/core";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { fmtTime, shortHash, timeAgo } from "@/lib/format";
import { EventSheet } from "./event-sheet";
import { OutcomeBadge, outcomeRowClass } from "./outcome";

const OUTCOMES = [
  ["", "All outcomes"],
  ["denied", "Denied"],
  ["error", "Errors"],
  ["allowed", "Allowed"],
] as const;

export function Timeline({ tenant, agents }: { tenant: string; agents: string[] }) {
  const [events, setEvents] = useState<SealedRecord[]>([]);
  const [outcome, setOutcome] = useState("");
  const [agent, setAgent] = useState("");
  const [action, setAction] = useState("");
  const [loading, setLoading] = useState(true);
  const [more, setMore] = useState(true);
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState<SealedRecord | null>(null);
  const fresh = useRef<Set<string>>(new Set());

  const query = useCallback(
    (extra: Record<string, string>) => {
      const q = new URLSearchParams({ tenant, limit: "50", ...extra });
      if (outcome) q.set("outcome", outcome);
      if (agent) q.set("agent_id", agent);
      if (action) q.set("action", action);
      return fetch(`/api/at/v1/events?${q}`).then((r) => r.json()).then((d) => (d.events ?? []) as SealedRecord[]);
    },
    [tenant, outcome, agent, action],
  );

  useEffect(() => {
    let cancel = false;
    setLoading(true);
    query({ order: "desc" }).then((evs) => {
      if (cancel) return;
      setEvents(evs);
      setMore(evs.length === 50);
      setLoading(false);
    });
    return () => {
      cancel = true;
    };
  }, [query]);

  useEffect(() => {
    if (!live) return;
    const t = setInterval(async () => {
      const head = events[0]?.seq ?? 0;
      const evs = await query({ order: "asc", after_seq: String(head) });
      if (evs.length) {
        evs.forEach((e) => fresh.current.add(e.id));
        setEvents((cur) => [...evs.reverse(), ...cur]);
      }
    }, 3000);
    return () => clearInterval(t);
  }, [live, events, query]);

  const loadMore = async () => {
    const last = events[events.length - 1];
    if (!last) return;
    const evs = await query({ order: "desc", before_seq: String(last.seq) });
    setEvents((cur) => [...cur, ...evs]);
    setMore(evs.length === 50);
  };

  return (
    <div className="rounded-xl border bg-background">
      <div className="flex flex-wrap items-center gap-2 border-b p-3">
        <div className="flex rounded-lg bg-muted p-0.5">
          {OUTCOMES.map(([v, label]) => (
            <button
              key={v}
              onClick={() => setOutcome(v)}
              className={cn("rounded-md px-2.5 py-1 text-xs text-muted-foreground", outcome === v && "bg-background font-medium text-foreground shadow-sm")}
            >
              {label}
            </button>
          ))}
        </div>
        <select value={agent} onChange={(e) => setAgent(e.target.value)} className="h-8 rounded-lg border bg-background px-2 text-xs">
          <option value="">All agents</option>
          {agents.map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <Input placeholder="action, e.g. mcp.tools/call" value={action} onChange={(e) => setAction(e.target.value)} className="h-8 w-56 text-xs" />
        <button onClick={() => setLive(!live)} className={cn("ml-auto inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-xs", live ? "text-emerald-700" : "text-muted-foreground")}>
          <RadioIcon className={cn("size-3.5", live && "animate-pulse")} /> {live ? "Live" : "Paused"}
        </button>
      </div>
      {loading ? (
        <div className="flex items-center gap-2 p-6 text-sm text-muted-foreground"><LoaderIcon className="size-4 animate-spin" /> Loading…</div>
      ) : events.length === 0 ? (
        <div className="p-10 text-center text-sm text-muted-foreground">No events match. Send one with the SDK or wrap an MCP server with the proxy.</div>
      ) : (
        <ul className="divide-y">
          {events.map((e) => (
            <li
              key={e.id}
              onClick={() => setSelected(e)}
              className={cn(
                "grid cursor-pointer grid-cols-[70px_92px_minmax(0,1.3fr)_minmax(0,1fr)_110px] items-center gap-3 px-4 py-2.5 text-[13px] transition-colors hover:bg-muted/60",
                outcomeRowClass[e.outcome],
                fresh.current.has(e.id) && "animate-in fade-in slide-in-from-top-1",
              )}
            >
              <span className="font-mono text-xs text-muted-foreground">#{e.seq}</span>
              <OutcomeBadge outcome={e.outcome} className="w-fit" />
              <div className="min-w-0">
                <div className="truncate font-medium">{title(e)}</div>
                <div className="truncate font-mono text-[11px] text-muted-foreground" title={e.target_resource}>{e.action} · {e.target_resource}</div>
              </div>
              <div className="min-w-0 text-xs">
                <div className="flex items-center gap-1 truncate"><UserIcon className="size-3 shrink-0 text-muted-foreground" />{e.human_principal_id ?? <span className="text-muted-foreground">autonomous</span>}</div>
                <div className="flex items-center gap-1 truncate text-muted-foreground"><BotIcon className="size-3 shrink-0" />{e.agent_id}{e.model_id && e.model_id !== "unknown" ? ` · ${e.model_id}` : ""}</div>
              </div>
              <div className="text-right text-xs text-muted-foreground" title={fmtTime(e.timestamp)}>
                <div>{timeAgo(e.timestamp)}</div>
                <div className="font-mono text-[10px]">{shortHash(e.hash, 8)}</div>
              </div>
            </li>
          ))}
        </ul>
      )}
      {more && !loading && (
        <div className="border-t p-2 text-center">
          <Button variant="ghost" size="sm" onClick={loadMore}>Load older</Button>
        </div>
      )}
      <EventSheet event={selected} tenant={tenant} onClose={() => setSelected(null)} />
    </div>
  );
}

/** Lead with what was touched: the tool / resource / prompt name for MCP actions. */
function title(e: SealedRecord): string {
  const m = /^mcp:\/\/([^/]+)\/(tools|prompts|resources)\/(.+)$/.exec(e.target_resource);
  if (m) return `${m[3]}  ·  ${decodeURIComponent(m[1]!)}`;
  return e.action;
}
