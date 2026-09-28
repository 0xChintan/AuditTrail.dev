"use client";

import { useState, useTransition } from "react";
import { KeyRoundIcon, RotateCwIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "@/components/at/toast";
import { createApiKey, revokeApiKey, rotateSigningKey } from "@/app/actions";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { fmtTime, timeAgo } from "@/lib/format";
import type { ApiKey, PublicKey } from "@/lib/types";
import { CopyButton } from "./copy";

export function KeysPanel({ tenant, keys, signing }: { tenant: string; keys: ApiKey[]; signing: PublicKey[] }) {
  const [name, setName] = useState("");
  const [fresh, setFresh] = useState<string | null>(null);
  const [pending, start] = useTransition();
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-[15px]">API keys</CardTitle>
          <CardDescription>Stored only as SHA-256 hashes. Rotate every 90 days: create the new key, deploy it, then revoke the old one.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {fresh && (
            <div className="rounded-lg border border-amber-500/40 bg-amber-50 p-3 text-sm">
              <div className="mb-1.5 flex items-center gap-1.5 font-medium text-amber-900"><TriangleAlertIcon className="size-4" /> Copy now. This key will not be shown again.</div>
              <div className="flex items-center gap-2 rounded-md bg-background px-2 py-1.5 font-mono text-[13px]"><span className="truncate">{fresh}</span><CopyButton value={fresh} className="ml-auto" /></div>
            </div>
          )}
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              start(async () => {
                const r = await createApiKey(tenant, name.trim());
                if (!r.ok) return void toast.error(r.error);
                setFresh(r.data.api_key);
                setName("");
                toast.success("API key created");
              });
            }}
          >
            <Input placeholder="Key name, e.g. prod-mcp-proxy" value={name} onChange={(e) => setName(e.target.value)} className="max-w-xs" />
            <Button type="submit" disabled={pending}><KeyRoundIcon /> Create key</Button>
          </form>
          <Table>
            <TableHeader>
              <TableRow><TableHead>Name</TableHead><TableHead>Prefix</TableHead><TableHead>Created</TableHead><TableHead>Last used</TableHead><TableHead>Status</TableHead><TableHead /></TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((k) => (
                <TableRow key={k.id} className={k.revoked_at ? "opacity-50" : ""}>
                  <TableCell>{k.name}</TableCell>
                  <TableCell className="font-mono text-xs">at_{k.prefix}_…</TableCell>
                  <TableCell className="text-xs">{fmtTime(k.created_at)}</TableCell>
                  <TableCell className="text-xs">{k.last_used_at ? timeAgo(k.last_used_at) : "never"}</TableCell>
                  <TableCell className="text-xs">{k.revoked_at ? `revoked ${timeAgo(k.revoked_at)}` : "active"}</TableCell>
                  <TableCell className="text-right">
                    {!k.revoked_at && (
                      <Button
                        size="sm"
                        variant="destructive"
                        disabled={pending}
                        onClick={() => {
                          if (!confirm(`Revoke "${k.name}"? Clients using it will get 401 immediately.`)) return;
                          start(async () => {
                            const r = await revokeApiKey(tenant, k.id);
                            r.ok ? toast.success("Key revoked") : toast.error(r.error);
                          });
                        }}
                      >
                        Revoke
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-[15px]">Ed25519 signing keys</CardTitle>
          <CardDescription>
            One key pair per tenant. Rows and checkpoints record which key signed them, so retired keys stay published and old records keep verifying.
            Public keys are served unauthenticated at <code className="text-xs">/v1/tenants/{tenant.slice(0, 8)}…/public-keys</code>.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Table>
            <TableHeader><TableRow><TableHead>Key id</TableHead><TableHead>Public key</TableHead><TableHead>Created</TableHead><TableHead>Status</TableHead></TableRow></TableHeader>
            <TableBody>
              {signing.map((k) => (
                <TableRow key={k.key_id}>
                  <TableCell className="font-mono text-xs">{k.key_id}</TableCell>
                  <TableCell className="font-mono text-xs">{k.public_key} <CopyButton value={k.public_key} /></TableCell>
                  <TableCell className="text-xs">{k.created_at && fmtTime(k.created_at)}</TableCell>
                  <TableCell className="text-xs">{k.retired_at ? `retired ${timeAgo(k.retired_at)}` : <b className="text-emerald-700">active</b>}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Button
            variant="outline"
            disabled={pending}
            onClick={() => {
              if (!confirm("Rotate the signing key? New records will be signed with a new key. The rotation is recorded in the ledger.")) return;
              start(async () => {
                const r = await rotateSigningKey(tenant);
                r.ok ? toast.success(`Rotated to ${r.data.key_id}`) : toast.error(r.error);
              });
            }}
          >
            <RotateCwIcon /> Rotate signing key
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
