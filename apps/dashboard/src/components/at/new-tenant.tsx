"use client";

import { useState, useTransition } from "react";
import { KeyRoundIcon, PlusIcon, TriangleAlertIcon } from "lucide-react";
import { toast } from "sonner";
import { createTenant } from "@/app/actions";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { CodeBlock, CopyButton } from "./copy";
import { setupSnippets } from "./snippets";
import Link from "next/link";

export function NewTenant({ apiUrl }: { apiUrl: string }) {
  const [name, setName] = useState("");
  const [retention, setRetention] = useState(183);
  const [pending, start] = useTransition();
  const [created, setCreated] = useState<{ id: string; name: string; key: string } | null>(null);

  if (created) {
    const s = setupSnippets(created.key, apiUrl);
    return (
      <Card className="border-emerald-600/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><KeyRoundIcon className="size-4 text-emerald-600" /> {created.name} is ready</CardTitle>
          <CardDescription>A genesis chain, a per-tenant Ed25519 signing key and an API key were created.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border border-amber-500/40 bg-amber-50 p-3 text-sm dark:bg-amber-500/10">
            <div className="mb-1.5 flex items-center gap-1.5 font-medium text-amber-900 dark:text-amber-300">
              <TriangleAlertIcon className="size-4" /> Copy this API key now. It is stored only as a hash and cannot be shown again.
            </div>
            <div className="flex items-center gap-2 rounded-md bg-background px-2 py-1.5 font-mono text-[13px]">
              <span className="truncate">{created.key}</span>
              <CopyButton value={created.key} className="ml-auto" />
            </div>
          </div>
          <Tabs defaultValue="mcp">
            <TabsList>
              <TabsTrigger value="mcp">MCP agent (no code)</TabsTrigger>
              <TabsTrigger value="claude">Claude Code</TabsTrigger>
              <TabsTrigger value="sdk">App SDK</TabsTrigger>
              <TabsTrigger value="curl">curl</TabsTrigger>
            </TabsList>
            <TabsContent value="mcp" className="mt-3 space-y-2">
              <p className="text-sm text-muted-foreground">Wrap any MCP server in your agent&apos;s config. Every tool call is recorded with its identity chain.</p>
              <CodeBlock code={s.mcp} />
            </TabsContent>
            <TabsContent value="claude" className="mt-3"><CodeBlock code={s.claude} /></TabsContent>
            <TabsContent value="sdk" className="mt-3"><CodeBlock code={s.sdk} /></TabsContent>
            <TabsContent value="curl" className="mt-3"><CodeBlock code={s.curl} /></TabsContent>
          </Tabs>
          <div className="flex gap-2">
            <Link href={`/t/${created.id}`}><Button>Open {created.name}</Button></Link>
            <Button variant="outline" onClick={() => setCreated(null)}>Create another</Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><PlusIcon className="size-4" /> Onboard a tenant</CardTitle>
        <CardDescription>Each tenant gets its own hash chain, signing key, API keys, retention policy and legal hold.</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="grid gap-4 sm:grid-cols-[1fr_180px_auto] sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            start(async () => {
              const r = await createTenant({ name: name.trim(), retention_days: retention });
              if (!r.ok) return void toast.error(r.error);
              setCreated({ id: r.data.tenant.id, name: r.data.tenant.name, key: r.data.api_key });
              setName("");
            });
          }}
        >
          <div className="grid gap-1.5">
            <Label htmlFor="tname">Name</Label>
            <Input id="tname" required placeholder="Acme Health: prior-auth agents" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="tret">Retention (days)</Label>
            <Input id="tret" type="number" min={183} value={retention} onChange={(e) => setRetention(Number(e.target.value))} />
          </div>
          <Button type="submit" disabled={pending || !name.trim()}>{pending ? "Creating…" : "Create tenant"}</Button>
        </form>
        <p className="mt-2 text-xs text-muted-foreground">Minimum 183 days (EU AI Act Art. 19(1) / 26(6): logs kept at least six months). Enforced by the database.</p>
      </CardContent>
    </Card>
  );
}
