"use client";

import { useState } from "react";
import { FileJsonIcon, FileSpreadsheetIcon, FileTextIcon } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { buttonVariants } from "@/components/ui/button";
import type { Template } from "@/lib/types";

export function ExportCard({ t, tenant, retentionDays }: { t: Template; tenant: string; retentionDays: number }) {
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const href = (format: string) => {
    const q = new URLSearchParams({ tenant, template: t.id, format });
    if (from) q.set("from", from);
    if (to) q.set("to", to);
    return `/api/at/v1/export?${q}`;
  };
  // v2 evidence bundle: tree heads + witness cosignatures + proofs, for `audittrail-verify --log-key --witness`.
  const bundleV2 = () => {
    const q = new URLSearchParams({ tenant });
    if (from) q.set("from", from);
    if (to) q.set("to", to);
    return `/api/at/v2/export?${q}`;
  };
  const meets = retentionDays >= t.min_retention_days;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-[15px]">{t.title}</CardTitle>
        <CardDescription>{t.source}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">{t.summary}</p>
        <div className="flex flex-wrap gap-1">
          {t.clauses.map((c) => (
            <span key={c.ref} title={c.requirement} className="rounded-md border bg-muted/50 px-1.5 py-0.5 font-mono text-[11px]">{c.ref}</span>
          ))}
        </div>
        <div className={`rounded-md px-2 py-1.5 text-xs ${meets ? "bg-emerald-50 text-emerald-800" : "bg-amber-50 text-amber-900"}`}>
          Retention {retentionDays} days {meets ? "meets" : "is below"} the {t.min_retention_days}-day guideline for {t.retention_clause}.
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="grid gap-1"><Label className="text-xs">From</Label><Input type="date" value={from} onChange={(e) => setFrom(e.target.value)} /></div>
          <div className="grid gap-1"><Label className="text-xs">To</Label><Input type="date" value={to} onChange={(e) => setTo(e.target.value)} /></div>
        </div>
        <div className="flex flex-wrap gap-2">
          <a className={buttonVariants({ size: "sm" })} href={href("pdf")}><FileTextIcon /> PDF report</a>
          <a className={buttonVariants({ size: "sm", variant: "outline" })} href={href("csv")}><FileSpreadsheetIcon /> CSV</a>
          <a className={buttonVariants({ size: "sm", variant: "outline" })} href={bundleV2()}><FileJsonIcon /> Evidence bundle</a>
          <a className={buttonVariants({ size: "sm", variant: "ghost" })} href={href("bundle")} title="Legacy v1 bundle (checkpoints + RFC 3161 anchors) for v1-era records"><FileJsonIcon /> v1 bundle</a>
        </div>
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground">Field → clause mapping</summary>
          <table className="mt-2 w-full">
            <tbody>
              {t.fields.map((f) => (
                <tr key={f.field} className="border-t align-top">
                  <td className="py-1 pr-2 font-mono">{f.label}</td>
                  <td className="py-1 pr-2 whitespace-nowrap">{f.clauses.join("; ")}</td>
                  <td className="py-1 text-muted-foreground">{f.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      </CardContent>
    </Card>
  );
}
