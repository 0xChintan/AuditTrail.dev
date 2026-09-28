"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { BadgeCheckIcon, BuildingIcon, LogOutIcon, ShieldCheckIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export function Sidebar({ tenants, operator, sso }: { tenants: { id: string; name: string; legal_hold: boolean }[]; operator?: string | null; sso?: boolean }) {
  const path = usePathname();
  const item = (href: string, active: boolean, children: React.ReactNode) => (
    <Link
      href={href}
      className={cn(
        "flex items-center gap-2 rounded-md px-2.5 py-1.5 text-[13px] text-zinc-400 transition-colors hover:bg-zinc-800/70 hover:text-zinc-100",
        active && "bg-zinc-800 text-zinc-50",
      )}
    >
      {children}
    </Link>
  );
  return (
    <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-zinc-800 bg-zinc-950 px-3 py-4 md:flex">
      <Link href="/" className="mb-6 flex items-center gap-2 px-2">
        <span className="grid size-7 place-items-center rounded-md bg-emerald-500/15 text-emerald-400 ring-1 ring-emerald-500/30">
          <ShieldCheckIcon className="size-4" />
        </span>
        <span className="text-sm font-semibold tracking-tight text-zinc-50">AuditTrail</span>
      </Link>
      <nav className="flex flex-col gap-0.5">
        {item("/", path === "/", <><BuildingIcon className="size-4" /> Tenants</>)}
        {item("/verify", path.startsWith("/verify"), <><BadgeCheckIcon className="size-4" /> Verify evidence</>)}
      </nav>
      <div className="mt-6 px-2.5 text-[11px] font-medium uppercase tracking-wider text-zinc-500">Tenants</div>
      <nav className="mt-1.5 flex flex-col gap-0.5 overflow-y-auto">
        {tenants.map((t) =>
          item(
            `/t/${t.id}`,
            path.startsWith(`/t/${t.id}`),
            <>
              <span className={cn("size-1.5 shrink-0 rounded-full", t.legal_hold ? "bg-amber-400" : "bg-zinc-600")} />
              <span className="truncate">{t.name}</span>
            </>,
          ),
        )}
        {tenants.length === 0 && <p className="px-2.5 text-xs text-zinc-500">None yet</p>}
      </nav>
      <p className="mt-auto px-2.5 text-[11px] leading-relaxed text-zinc-500">
        Hash-chained, Ed25519-signed, RFC 3161-anchored audit ledger for AI agents.
      </p>
      {sso && (
        <div className="mt-3 border-t border-zinc-800 px-2.5 pt-3">
          {operator && <p className="truncate text-xs text-zinc-300" title={operator}>{operator}</p>}
          <form method="post" action="/auth/logout">
            <button type="submit" className="mt-1.5 flex items-center gap-1.5 text-xs text-zinc-500 transition-colors hover:text-zinc-200">
              <LogOutIcon className="size-3.5" /> Sign out
            </button>
          </form>
        </div>
      )}
    </aside>
  );
}
