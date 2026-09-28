"use client";

import { useEffect, useState } from "react";
import { ShieldAlertIcon, ShieldCheckIcon, LoaderIcon } from "lucide-react";
import type { ServerReport } from "@/lib/types";
import { cn } from "@/lib/utils";

/** Runs the full chain verification (server-side recomputation) and shows the result. */
export function VerifyStatus({ tenant }: { tenant: string }) {
  const [r, setR] = useState<ServerReport | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    fetch(`/api/at/v1/verify?tenant=${tenant}`)
      .then(async (res) => (res.ok ? setR(await res.json()) : setErr((await res.json()).error?.message ?? `HTTP ${res.status}`)))
      .catch((e) => setErr(String(e)));
  }, [tenant]);
  if (err) return <div className="text-sm text-red-600">{err}</div>;
  if (!r)
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <LoaderIcon className="size-4 animate-spin" /> Recomputing every hash, link and signature…
      </div>
    );
  const anchored = r.anchors.filter((a) => a.status === "verified").length;
  const errors = r.issues.filter((i) => i.severity === "error");
  return (
    <div className="space-y-2">
      <div className={cn("flex items-center gap-2 font-medium", r.ok ? "text-emerald-700" : "text-red-700")}>
        {r.ok ? <ShieldCheckIcon className="size-5" /> : <ShieldAlertIcon className="size-5" />}
        {r.ok ? "Chain intact" : `Tampering detected at seq ${r.tampered_seqs.slice(0, 8).join(", ")}${r.tampered_seqs.length > 8 ? "…" : ""}`}
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <dt>Hashes recomputed</dt><dd className="text-right tabular-nums text-foreground">{r.events_checked}</dd>
        <dt>Signatures valid</dt><dd className="text-right tabular-nums text-foreground">{r.signatures_verified}/{r.events_checked}</dd>
        <dt>Checkpoints</dt><dd className="text-right tabular-nums text-foreground">{r.checkpoints_checked}</dd>
        <dt>RFC 3161 anchors verified</dt><dd className="text-right tabular-nums text-foreground">{anchored}/{r.anchors.length}</dd>
        <dt>Chain starts at</dt><dd className="truncate text-right text-foreground">{r.chain_start || "—"}</dd>
      </dl>
      {errors.slice(0, 4).map((i, k) => (
        <div key={k} className="rounded-md bg-red-50 px-2 py-1 text-xs text-red-800 dark:bg-red-500/10 dark:text-red-300">
          <b>{i.kind}</b> {i.detail}
        </div>
      ))}
    </div>
  );
}
