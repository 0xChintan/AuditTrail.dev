import { notFound } from "next/navigation";
import { LockIcon } from "lucide-react";
import { CopyButton } from "@/components/at/copy";
import { TenantTabs } from "@/components/at/tenant-tabs";
import { api, ApiError } from "@/lib/api";
import type { Tenant } from "@/lib/types";

export default async function TenantLayout({ children, params }: LayoutProps<"/t/[id]">) {
  const { id } = await params;
  const t = await api<Tenant>(`/v1/admin/tenants/${id}`).catch((e) => {
    if (e instanceof ApiError && (e.status === 404 || e.status === 400)) notFound();
    throw e;
  });
  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-3 bg-background px-8 pb-4 pt-7">
        <div>
          <div className="text-xs font-medium text-muted-foreground">Tenant</div>
          <h1 className="text-xl font-semibold tracking-tight">{t.name}</h1>
          <div className="mt-1 flex items-center gap-1 font-mono text-[11px] text-muted-foreground">
            {t.id} <CopyButton value={t.id} />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="rounded-md border px-2 py-1 text-muted-foreground">retention <b className="text-foreground">{t.retention_days} days</b></span>
          <span className="rounded-md border px-2 py-1 text-muted-foreground">rate limit <b className="text-foreground">{t.rate_limit_rps}/s</b></span>
          {t.legal_hold && (
            <span className="inline-flex items-center gap-1 rounded-md bg-amber-100 px-2 py-1 font-medium text-amber-900" title={t.legal_hold_reason ?? ""}>
              <LockIcon className="size-3" /> Legal hold: {t.legal_hold_reason}
            </span>
          )}
        </div>
      </div>
      <TenantTabs id={t.id} />
      <div className="px-8 py-6">{children}</div>
    </div>
  );
}
