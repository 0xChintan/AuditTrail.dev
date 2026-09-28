"use client";

import { CheckIcon, CopyIcon } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

export function CopyButton({ value, className, label }: { value: string; className?: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      title="Copy"
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
      className={cn("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs text-muted-foreground hover:bg-muted hover:text-foreground", className)}
    >
      {done ? <CheckIcon className="size-3.5 text-emerald-600" /> : <CopyIcon className="size-3.5" />}
      {label}
    </button>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <code className={cn("font-mono text-[12px] break-all", className)}>{children}</code>;
}

export function CodeBlock({ code, className }: { code: string; className?: string }) {
  return (
    <div className={cn("group relative rounded-lg border bg-zinc-950 text-zinc-100", className)}>
      <CopyButton value={code} className="absolute right-2 top-2 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100" />
      <pre className="overflow-x-auto p-3 pr-10 text-[12px] leading-relaxed"><code>{code}</code></pre>
    </div>
  );
}
