"use client";

import { useState } from "react";
import { CheckCircle2Icon, FileUpIcon, InfoIcon, LoaderIcon, ShieldAlertIcon, ShieldCheckIcon, XCircleIcon } from "lucide-react";
import {
  canonicalPayload, ed25519Verify, utf8, verifyBundle, verifyInclusion, verifyRecord,
  type Bundle, type BundleReport, type Checkpoint, type PublicKey, type SealedRecord,
} from "@audittrail/core";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";

type Check = { label: string; ok: boolean | null; detail?: string };

function Checks({ checks, title }: { checks: Check[]; title?: string }) {
  const allOk = checks.every((c) => c.ok !== false);
  return (
    <div className={cn("rounded-xl border p-4", allOk ? "border-emerald-600/30 bg-emerald-50/50 dark:bg-emerald-500/5" : "border-red-600/30 bg-red-50/50 dark:bg-red-500/5")}>
      <div className={cn("mb-3 flex items-center gap-2 font-semibold", allOk ? "text-emerald-800 dark:text-emerald-400" : "text-red-800 dark:text-red-400")}>
        {allOk ? <ShieldCheckIcon className="size-5" /> : <ShieldAlertIcon className="size-5" />}
        {title ?? (allOk ? "Verified in your browser" : "Verification failed")}
      </div>
      <ul className="space-y-2">
        {checks.map((c, i) => (
          <li key={i} className="flex items-start gap-2 text-sm">
            {c.ok === true ? <CheckCircle2Icon className="mt-0.5 size-4 shrink-0 text-emerald-600" /> : c.ok === false ? <XCircleIcon className="mt-0.5 size-4 shrink-0 text-red-600" /> : <InfoIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />}
            <div className="min-w-0">
              <div>{c.label}</div>
              {c.detail && <div className="font-mono text-[11px] text-muted-foreground break-all">{c.detail}</div>}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function parseKeys(text: string): PublicKey[] | null {
  const t = text.trim();
  if (!t) return null;
  if (/^[A-Za-z0-9+/=_-]{40,48}$/.test(t)) return [{ key_id: "*", algorithm: "ed25519", public_key: t }];
  const v = JSON.parse(t);
  if (Array.isArray(v)) return v;
  if (Array.isArray(v.keys)) return v.keys;
  if (Array.isArray(v.public_keys)) return v.public_keys;
  throw new Error("unrecognized public key format");
}

async function resolveKeys(pasted: string, tenantId: string): Promise<{ keys: PublicKey[]; source: string }> {
  const k = parseKeys(pasted);
  if (k) return { keys: k, source: "pasted by you" };
  const res = await fetch(`/api/pubkeys/${tenantId}`);
  if (!res.ok) throw new Error(`could not fetch public keys for tenant ${tenantId}`);
  return { keys: (await res.json()).keys, source: "fetched from this AuditTrail deployment" };
}

function withWildcard(keys: PublicKey[], keyId: string): PublicKey[] {
  return keys.map((k) => (k.key_id === "*" ? { ...k, key_id: keyId } : k));
}

// ---- 1. single record ---------------------------------------------------------

function RecordVerifier() {
  const [rec, setRec] = useState("");
  const [prev, setPrev] = useState("");
  const [keys, setKeys] = useState("");
  const [res, setRes] = useState<{ checks: Check[]; canonical: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try {
      const r = JSON.parse(rec) as SealedRecord;
      const p = prev.trim() ? (JSON.parse(prev) as SealedRecord) : null;
      const { keys: ks, source } = await resolveKeys(keys, r.tenant_id);
      const out = await verifyRecord(r, withWildcard(ks, r.key_id), p);
      const checks: Check[] = [
        { label: "Hash recomputed from the record's own content matches its hash", ok: out.hashMatches, detail: `recomputed ${out.recomputedHash}` },
        { label: `Ed25519 signature by ${r.key_id} (public key ${source})`, ok: out.signatureValid },
      ];
      if (out.linkValid !== null) checks.push({ label: p ? `Links to previous record #${p.seq}` : "First record links to genesis", ok: out.linkValid });
      else checks.push({ label: "Chain link not checked (paste the previous record to check it)", ok: null });
      setRes({ checks, canonical: canonicalPayload(r) });
    } catch (e) {
      setRes({ checks: [{ label: String((e as Error).message ?? e), ok: false }], canonical: "" });
    }
    setBusy(false);
  };
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="space-y-3">
        <div className="grid gap-1.5"><Label>Sealed record (JSON)</Label><Textarea className="h-56 font-mono text-xs" placeholder='{"id":"…","seq":42,"hash":"…","signature":"…", …}' value={rec} onChange={(e) => setRec(e.target.value)} /></div>
        <div className="grid gap-1.5"><Label>Previous record (optional, for the chain link)</Label><Textarea className="h-20 font-mono text-xs" value={prev} onChange={(e) => setPrev(e.target.value)} /></div>
        <div className="grid gap-1.5">
          <Label>Tenant public key(s) (optional)</Label>
          <Textarea className="h-16 font-mono text-xs" placeholder="base64 Ed25519 key or the JSON from /v1/tenants/{id}/public-keys. Leave empty to fetch." value={keys} onChange={(e) => setKeys(e.target.value)} />
        </div>
        <Button onClick={run} disabled={busy || !rec.trim()}>{busy && <LoaderIcon className="animate-spin" />} Verify record</Button>
      </div>
      <div className="space-y-3">
        {res ? <Checks checks={res.checks} /> : <Explainer />}
        {res?.canonical && (
          <details className="text-xs" open>
            <summary className="cursor-pointer text-muted-foreground">Canonical payload (RFC 8785) that was hashed</summary>
            <pre className="mt-2 overflow-auto rounded-lg bg-muted p-3 text-[11px] break-all whitespace-pre-wrap">{res.canonical}</pre>
          </details>
        )}
      </div>
    </div>
  );
}

// ---- 2. inclusion proof ---------------------------------------------------------

function ProofVerifier() {
  const [text, setText] = useState("");
  const [checks, setChecks] = useState<Check[] | null>(null);
  const run = async () => {
    try {
      const p = JSON.parse(text) as { event: SealedRecord; checkpoint: Checkpoint; leaf_index: number; tree_size: number; inclusion_path: string[]; public_keys: PublicKey[] };
      const rc = await verifyRecord(p.event, p.public_keys);
      const st = JSON.parse(p.checkpoint.statement);
      const pk = p.public_keys.find((k) => k.key_id === p.checkpoint.key_id)?.public_key ?? "";
      const out: Check[] = [
        { label: "Record hash recomputed from content", ok: rc.hashMatches },
        { label: "Record Ed25519 signature", ok: rc.signatureValid },
        { label: `Merkle inclusion: leaf ${p.leaf_index + 1} of ${p.tree_size} → checkpoint root`, ok: await verifyInclusion(p.event.hash, p.leaf_index, p.tree_size, p.inclusion_path, p.checkpoint.merkle_root), detail: p.checkpoint.merkle_root },
        { label: "Checkpoint statement contains exactly this root and range", ok: st.merkle_root === p.checkpoint.merkle_root && st.first_seq <= p.event.seq && p.event.seq <= st.last_seq },
        { label: "Checkpoint statement signed by the tenant key", ok: await ed25519Verify(pk, utf8(p.checkpoint.statement), p.checkpoint.signature) },
        p.checkpoint.external_anchor_proof
          ? { label: `RFC 3161 time-stamp present (${p.checkpoint.anchor_authority ?? "TSA"}, ${p.checkpoint.anchored_at ?? ""}). Validate the TSA's CMS signature with audittrail-verify.`, ok: null }
          : { label: `No external anchor yet (status ${p.checkpoint.anchor_status})`, ok: null },
      ];
      setChecks(out);
    } catch (e) {
      setChecks([{ label: String((e as Error).message ?? e), ok: false }]);
    }
  };
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="space-y-3">
        <div className="grid gap-1.5">
          <Label>Inclusion proof (JSON from GET /v1/events/&#123;id&#125;/proof)</Label>
          <Textarea className="h-72 font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <Button onClick={run} disabled={!text.trim()}>Verify proof</Button>
      </div>
      {checks ? <Checks checks={checks} /> : <Explainer />}
    </div>
  );
}

// ---- 3. evidence bundle ---------------------------------------------------------

function BundleVerifier() {
  const [report, setReport] = useState<BundleReport | null>(null);
  const [name, setName] = useState("");
  const [progress, setProgress] = useState<[number, number] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const onFile = async (f: File) => {
    setName(f.name);
    setReport(null);
    setErr(null);
    try {
      const b = JSON.parse(await f.text()) as Bundle;
      setReport(await verifyBundle(b, (d, t) => setProgress([d, t])));
    } catch (e) {
      setErr(String((e as Error).message ?? e));
    }
    setProgress(null);
  };
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <label
        className="flex h-56 cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed text-sm text-muted-foreground hover:bg-muted/40"
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const f = e.dataTransfer.files[0];
          if (f) void onFile(f);
        }}
      >
        <FileUpIcon className="size-6" />
        <span>Drop an evidence bundle (<code>*.bundle.json</code>) or click to choose</span>
        {name && <span className="font-mono text-xs text-foreground">{name}</span>}
        {progress && <span>Verifying {progress[0]} / {progress[1]}…</span>}
        <input type="file" accept=".json,application/json" className="hidden" onChange={(e) => e.target.files?.[0] && onFile(e.target.files[0])} />
      </label>
      <div>
        {err && <Checks checks={[{ label: err, ok: false }]} />}
        {report && (
          <Checks
            title={report.ok ? `Bundle verified: ${report.eventsChecked} records, seq ${report.firstSeq}–${report.lastSeq}` : `Tampering detected at seq ${report.tamperedSeqs.join(", ")}`}
            checks={[
              { label: `${report.eventsChecked} hashes recomputed from content`, ok: !report.issues.some((i) => i.kind === "content_tampered") },
              { label: `${report.signaturesVerified}/${report.eventsChecked} Ed25519 signatures valid`, ok: report.signaturesVerified === report.eventsChecked },
              { label: `Chain links and seq continuity (starts at ${report.chainStart || "—"})`, ok: !report.issues.some((i) => ["link_broken", "seq_gap", "checkpoint_rows_missing"].includes(i.kind)) },
              { label: `${report.checkpointsChecked} checkpoint(s): Merkle roots + signatures`, ok: !report.issues.some((i) => i.kind.startsWith("checkpoint_") && i.severity === "error") },
              ...report.anchors.map((a) => ({ label: `Anchor for ${a.checkpoint_id.slice(0, 8)}: ${a.status}`, ok: null, detail: a.note })),
              ...report.issues.filter((i) => i.severity === "error").slice(0, 12).map((i) => ({ label: `${i.kind}${i.seq ? ` @ seq ${i.seq}` : ""}`, ok: false as const, detail: i.detail })),
            ]}
          />
        )}
        {!report && !err && <Explainer />}
      </div>
    </div>
  );
}

function Explainer() {
  return (
    <Card className="bg-muted/30">
      <CardHeader><CardTitle className="text-sm">What runs here</CardTitle></CardHeader>
      <CardContent className="space-y-2 text-sm text-muted-foreground">
        <p>Everything is computed in your browser with WebCrypto. Nothing is sent to a server, except fetching a tenant&apos;s public keys if you don&apos;t paste them.</p>
        <ol className="list-decimal space-y-1 pl-5">
          <li>Canonicalize the record (RFC 8785) and recompute <code>SHA-256(previous_hash ‖ payload)</code>.</li>
          <li>Check the tenant&apos;s Ed25519 signature over that hash.</li>
          <li>Check the link to the previous record, and Merkle inclusion in a signed checkpoint.</li>
        </ol>
      </CardContent>
    </Card>
  );
}

export function VerifyPortal() {
  return (
    <Tabs defaultValue="record">
      <TabsList>
        <TabsTrigger value="record">Single record</TabsTrigger>
        <TabsTrigger value="proof">Inclusion proof</TabsTrigger>
        <TabsTrigger value="bundle">Evidence bundle</TabsTrigger>
      </TabsList>
      <TabsContent value="record" className="mt-4"><RecordVerifier /></TabsContent>
      <TabsContent value="proof" className="mt-4"><ProofVerifier /></TabsContent>
      <TabsContent value="bundle" className="mt-4"><BundleVerifier /></TabsContent>
    </Tabs>
  );
}

