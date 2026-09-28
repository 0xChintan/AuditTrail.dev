import Link from "next/link";
import { ArrowRightIcon, LockIcon, ServerCrashIcon } from "lucide-react";
import { NewTenant } from "@/components/at/new-tenant";
import { PageHeader } from "@/components/at/page-header";
import { Card } from "@/components/ui/card";
import { api, API_URL } from "@/lib/api";
import { num, shortHash, timeAgo } from "@/lib/format";
import type { Stats, Tenant } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function Home() {
  let tenants: Tenant[] = [];
  let error: string | null = null;
  try {
    tenants = (await api<{ tenants: Tenant[] }>("/v1/admin/tenants")).tenants.reverse();
  } catch (e) {
    error = (e as Error).message;
  }
  const stats = await Promise.all(tenants.map((t) => api<Stats>("/v1/stats", { tenant: t.id }).catch(() => null)));
  const publicUrl = process.env.AUDITTRAIL_PUBLIC_API_URL ?? API_URL;

  return (
    <div>
      <PageHeader title="Tenants" description="Every tenant is an isolated, append-only, hash-chained ledger." />
      <div className="space-y-6 px-8 py-6">
        {error && (
          <Card className="flex items-center gap-3 border-red-500/40 p-4 text-sm text-red-700">
            <ServerCrashIcon className="size-5" /> {error}
          </Card>
        )}
        <NewTenant apiUrl={publicUrl} />
        <div className="grid gap-3 lg:grid-cols-2 2xl:grid-cols-3">
          {tenants.map((t, i) => {
            const s = stats[i];
            return (
              <Link key={t.id} href={`/t/${t.id}`} className="group">
                <Card className="gap-3 p-4 transition-shadow group-hover:shadow-md">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="truncate font-medium">{t.name}</div>
                      <div className="font-mono text-[11px] text-muted-foreground">{t.id}</div>
                    </div>
                    {t.legal_hold ? (
                      <span className="inline-flex items-center gap-1 rounded-md bg-amber-100 px-1.5 py-0.5 text-[11px] font-medium text-amber-900"><LockIcon className="size-3" /> legal hold</span>
                    ) : (
                      <ArrowRightIcon className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                    )}
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    {[
                      ["records", s?.total ?? 0, ""],
                      ["allowed", s?.by_outcome.allowed ?? 0, "text-emerald-700"],
                      ["denied", s?.by_outcome.denied ?? 0, "text-amber-700"],
                      ["errors", s?.by_outcome.error ?? 0, "text-red-700"],
                    ].map(([label, v, cls]) => (
                      <div key={label as string} className="rounded-md bg-muted/60 py-1.5">
                        <div className={`text-sm font-semibold tabular-nums ${cls}`}>{num(v as number)}</div>
                        <div className="text-[11px] text-muted-foreground">{label}</div>
                      </div>
                    ))}
                  </div>
                  <div className="flex justify-between text-[11px] text-muted-foreground">
                    <span>head <span className="font-mono">{shortHash(s?.head_hash)}</span> · seq {s?.head_seq ?? 0}</span>
                    <span>{t.retention_days}d retention · created {timeAgo(t.created_at)}</span>
                  </div>
                </Card>
              </Link>
            );
          })}
        </div>
      </div>
    </div>
  );
}
