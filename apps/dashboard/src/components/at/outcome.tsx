import { cn } from "@/lib/utils";

const styles = {
  allowed: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-400",
  denied: "bg-amber-50 text-amber-800 ring-amber-600/25 dark:bg-amber-500/10 dark:text-amber-400",
  error: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-400",
} as const;

export function OutcomeBadge({ outcome, className }: { outcome: string; className?: string }) {
  const s = styles[outcome as keyof typeof styles] ?? "bg-muted text-muted-foreground ring-border";
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", s, className)}>
      <span className={cn("size-1.5 rounded-full", outcome === "allowed" ? "bg-emerald-500" : outcome === "denied" ? "bg-amber-500" : "bg-red-500")} />
      {outcome}
    </span>
  );
}

export const outcomeRowClass: Record<string, string> = {
  allowed: "",
  denied: "bg-amber-50/60 dark:bg-amber-500/5",
  error: "bg-red-50/60 dark:bg-red-500/5",
};
