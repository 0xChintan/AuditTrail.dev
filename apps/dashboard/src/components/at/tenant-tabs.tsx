"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

export function TenantTabs({ id }: { id: string }) {
  const path = usePathname();
  const tabs = [
    ["Activity", `/t/${id}`],
    ["Checkpoints", `/t/${id}/checkpoints`],
    ["Compliance exports", `/t/${id}/exports`],
    ["Keys", `/t/${id}/keys`],
    ["Retention & settings", `/t/${id}/settings`],
  ];
  return (
    <div className="flex gap-1 border-b bg-background px-6">
      {tabs.map(([label, href]) => {
        const active = href === `/t/${id}` ? path === href : path.startsWith(href!);
        return (
          <Link
            key={href}
            href={href!}
            className={cn(
              "-mb-px border-b-2 border-transparent px-3 py-2.5 text-[13px] text-muted-foreground transition-colors hover:text-foreground",
              active && "border-foreground font-medium text-foreground",
            )}
          >
            {label}
          </Link>
        );
      })}
    </div>
  );
}
