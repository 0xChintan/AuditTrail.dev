"use client";

import { useState, useTransition } from "react";
import { LockIcon, LockOpenIcon } from "lucide-react";
import { toast } from "sonner";
import { updateSettings } from "@/app/actions";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import type { Tenant } from "@/lib/types";

export function SettingsForm({ t, purges }: { t: Tenant; purges: { purged_through_seq: number; rows_deleted: number; purged_at: string; performed_by: string }[] }) {
  const [retention, setRetention] = useState(t.retention_days);
  const [rps, setRps] = useState(t.rate_limit_rps);
  const [burst, setBurst] = useState(t.rate_limit_burst);
  const [reason, setReason] = useState("");
  const [pending, start] = useTransition();
  const save = (patch: Parameters<typeof updateSettings>[1], msg: string) =>
    start(async () => {
      const r = await updateSettings(t.id, patch);
      r.ok ? toast.success(msg) : toast.error(r.error);
    });

  return (
    <div className="grid gap-6 xl:grid-cols-2">
      <Card className={t.legal_hold ? "border-amber-500/50" : ""}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-[15px]">{t.legal_hold ? <LockIcon className="size-4 text-amber-600" /> : <LockOpenIcon className="size-4" />} Legal hold</CardTitle>
          <CardDescription>While a hold is active, the database refuses every purge, whatever the retention setting. Setting and releasing a hold are themselves ledger events.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {t.legal_hold ? (
            <>
              <div className="rounded-md bg-amber-50 p-3 text-sm text-amber-900">
                <b>Active</b> since {t.legal_hold_set_at && new Date(t.legal_hold_set_at).toUTCString()}
                <div className="mt-1">{t.legal_hold_reason}</div>
              </div>
              <Button variant="outline" disabled={pending} onClick={() => confirm("Release the legal hold? Purges past retention will be allowed again.") && save({ legal_hold: false }, "Legal hold released")}>
                Release hold
              </Button>
            </>
          ) : (
            <>
              <Label htmlFor="reason">Reason (required)</Label>
              <Textarea id="reason" placeholder="e.g. Litigation hold: case 2026-CV-0142, requested by legal@…" value={reason} onChange={(e) => setReason(e.target.value)} />
              <Button disabled={pending || !reason.trim()} onClick={() => save({ legal_hold: true, legal_hold_reason: reason.trim() }, "Legal hold set")}>
                <LockIcon /> Place legal hold
              </Button>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-[15px]">Retention</CardTitle>
          <CardDescription>Minimum 183 days (EU AI Act Art. 19(1) / 26(6)). Purges only remove whole checkpoint ranges that are already externally anchored, so the remaining chain stays verifiable.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-end gap-2">
            <div className="grid gap-1.5">
              <Label htmlFor="ret">Retention (days)</Label>
              <Input id="ret" type="number" min={183} value={retention} onChange={(e) => setRetention(Number(e.target.value))} className="w-40" />
            </div>
            <Button disabled={pending || retention === t.retention_days} onClick={() => save({ retention_days: retention }, "Retention updated")}>Save</Button>
          </div>
          <div className="text-xs text-muted-foreground">
            {purges.length === 0 ? "No purges have run for this tenant." : (
              <ul className="space-y-0.5">
                {purges.map((p, i) => <li key={i}>Purged {p.rows_deleted} rows through seq {p.purged_through_seq} on {new Date(p.purged_at).toUTCString()} ({p.performed_by})</li>)}
              </ul>
            )}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-[15px]">Ingestion rate limit</CardTitle>
          <CardDescription>A per-tenant token bucket on POST /v1/events. Over-limit requests get 429 with Retry-After, and the SDK and proxy retry them without losing events.</CardDescription>
        </CardHeader>
        <CardContent className="flex items-end gap-2">
          <div className="grid gap-1.5"><Label>Requests / second</Label><Input type="number" min={1} value={rps} onChange={(e) => setRps(Number(e.target.value))} className="w-32" /></div>
          <div className="grid gap-1.5"><Label>Burst</Label><Input type="number" min={1} value={burst} onChange={(e) => setBurst(Number(e.target.value))} className="w-32" /></div>
          <Button disabled={pending} onClick={() => save({ rate_limit_rps: rps, rate_limit_burst: burst }, "Rate limit updated")}>Save</Button>
        </CardContent>
      </Card>
    </div>
  );
}
