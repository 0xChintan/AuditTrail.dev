"use client";

import { useState } from "react";
import { CheckCircle2Icon, LoaderIcon, ShieldCheckIcon, XCircleIcon, InfoIcon } from "lucide-react";
import { canonicalPayload, type SealedRecord } from "@audittrail/core";
import { verifyBundleWasm } from "@/lib/wasm-verifier";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { fmtTime } from "@/lib/format";
import { CopyButton } from "./copy";
import { IdentityChain } from "./identity-chain";
import { OutcomeBadge } from "./outcome";

type Check = { label: string; ok: boolean | null; detail?: string };

function Row({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-2 py-1 text-xs">
      <dt className="text-muted-foreground">{k}</dt>
      <dd className={mono ? "font-mono break-all" : "break-words"}>{v}</dd>
    </div>
  );
}

export function EventSheet({ event, tenant, onClose }: { event: SealedRecord | null; tenant: string; onClose: () => void }) {
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [shown, setShown] = useState<string | null>(null);
  if (event && shown !== event.id) {
    setShown(event.id);
    setChecks(null);
  }

  async function verifyInBrowser(e: SealedRecord) {
    setBusy(true);
    const out: Check[] = [];
    try {
      // A minimal evidence bundle for this one row (widened to its signed tree
      // head), verified by the offline WASM verifier with the log key pinned.
      const [bundle, log] = await Promise.all([
        fetch(`/api/at/v2/export?tenant=${tenant}&from_seq=${e.seq}&to_seq=${e.seq}`).then((r) => r.text()),
        fetch(`/api/at/v2/tenants/${e.tenant_id}/log?tenant=${tenant}`).then((r) => r.json()),
      ]);
      const rep = await verifyBundleWasm(bundle, { log_keys: log.vkeys });
      const label: Record<string, string> = {
        "content-hash": "Hash recomputed from this record's content",
        "payload-hash": "Payload matches its payload_hash",
        "row-signature": `Receipt signature (${e.key_id})`,
        "chain-link": "Links to the previous record",
        "tree-root": "Reproduces the signed Merkle root of its tree head",
        "checkpoint-signature": "Tree head signed by the tenant log key (pinned)",
        consistency: "Tree heads are append-only",
        coverage: "Covered by a signed tree head",
      };
      for (const [inv, text] of Object.entries(label)) {
        const c = rep.checks[inv];
        if (!c) continue;
        const warn = rep.warnings.find((w) => w.invariant === inv);
        out.push({ label: text, ok: c.status === "pass" && !warn ? true : c.status === "fail" ? false : null, detail: warn?.detail ?? (c.status === "fail" ? c.detail : undefined) });
      }
      if (rep.witnessed_by?.length) out.push({ label: `Cosigned by ${rep.witnessed_by.length} witness(es): ${rep.witnessed_by.join(", ")}`, ok: null });
      if (rep.anchored_at) out.push({ label: `RFC 3161 anchor ${rep.anchored_at}`, ok: true });
    } catch (err) {
      out.push({ label: `Verification failed to run: ${String(err)}`, ok: false });
    }
    setChecks(out);
    setBusy(false);
  }

  const md = event?.metadata as Record<string, unknown> | null;
  const prov = (md?.identity_provenance ?? null) as Record<string, string> | null;
  return (
    <Sheet open={!!event} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
        {event && (
          <>
            <SheetHeader>
              <SheetTitle className="flex items-center gap-2">
                <span className="font-mono text-sm text-muted-foreground">#{event.seq}</span> {event.action} <OutcomeBadge outcome={event.outcome} />
              </SheetTitle>
              <SheetDescription className="font-mono text-xs break-all">{event.target_resource}</SheetDescription>
            </SheetHeader>
            <div className="space-y-5 px-4 pb-8">
              <section>
                <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Identity</h3>
                <dl>
                  <Row k="Human principal" v={<>{event.human_principal_id ?? <i>autonomous / none</i>} {prov && <Prov s={prov.human_principal_id} />}</>} />
                  <Row k="Agent" v={<>{event.agent_id} {prov && <Prov s={prov.agent_id} />}</>} />
                  <Row k="Model" v={<>{event.model_id ?? "—"}{event.model_version && event.model_version !== "unknown" ? `@${event.model_version}` : ""} {prov && <Prov s={prov.model_id} />}</>} />
                  <Row k="When" v={fmtTime(event.timestamp)} />
                </dl>
              </section>
              <section>
                <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Delegation chain</h3>
                <IdentityChain chain={event.delegation_chain} />
              </section>
              <section>
                <div className="mb-1 flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Integrity</h3>
                  <Button size="sm" variant="outline" disabled={busy} onClick={() => verifyInBrowser(event)}>
                    {busy ? <LoaderIcon className="size-3.5 animate-spin" /> : <ShieldCheckIcon className="size-3.5" />} Verify in this browser
                  </Button>
                </div>
                <dl>
                  <Row k="seq" v={event.seq} />
                  <Row k="hash" v={<>{event.hash} <CopyButton value={event.hash} /></>} mono />
                  <Row k="previous_hash" v={event.previous_hash} mono />
                  <Row k="signature" v={event.signature} mono />
                  <Row k="key_id" v={event.key_id} mono />
                </dl>
                {checks && (
                  <ul className="mt-2 space-y-1 rounded-lg border p-2">
                    {checks.map((c, i) => (
                      <li key={i} className="flex items-start gap-2 text-xs">
                        {c.ok === true ? <CheckCircle2Icon className="mt-px size-4 shrink-0 text-emerald-600" /> : c.ok === false ? <XCircleIcon className="mt-px size-4 shrink-0 text-red-600" /> : <InfoIcon className="mt-px size-4 shrink-0 text-muted-foreground" />}
                        <div className="min-w-0">
                          <div>{c.label}</div>
                          {c.detail && <div className="font-mono text-[10px] text-muted-foreground break-all">{c.detail}</div>}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
              <section>
                <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Metadata</h3>
                <pre className="max-h-80 overflow-auto rounded-lg bg-muted p-3 text-[11px] leading-relaxed">{JSON.stringify(event.metadata, null, 2)}</pre>
              </section>
              <details className="text-xs">
                <summary className="cursor-pointer text-muted-foreground">Canonical payload that was hashed</summary>
                <pre className="mt-2 overflow-auto rounded-lg bg-muted p-3 text-[11px] break-all whitespace-pre-wrap">{(event as { spec_version?: number }).spec_version === 2 ? "spec_version 2: the record hash is SHA-256 over length-prefixed fields (schemas/v2/SPEC.md §3); the payload is committed via payload_hash." : canonicalPayload(event)}</pre>
              </details>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

function Prov({ s }: { s?: string }) {
  if (!s) return null;
  const weak = s === "unavailable" || s.startsWith("inferred");
  return <span className={`ml-1 rounded px-1 text-[10px] ${weak ? "bg-amber-100 text-amber-900" : "bg-muted text-muted-foreground"}`}>via {s}</span>;
}
