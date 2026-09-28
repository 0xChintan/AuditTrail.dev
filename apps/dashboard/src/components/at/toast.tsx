"use client";

import { useSyncExternalStore } from "react";
import { CheckCircle2Icon, XCircleIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Minimal toasts. Replaces sonner, which injects <style> tags at runtime
 * and so would need 'unsafe-inline' under our strict CSP.
 */
type Toast = { id: number; kind: "success" | "error"; text: string };
let toasts: Toast[] = [];
let next = 1;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

function push(kind: Toast["kind"], text: string) {
  const id = next++;
  toasts = [...toasts, { id, kind, text }];
  emit();
  setTimeout(() => {
    toasts = toasts.filter((t) => t.id !== id);
    emit();
  }, 4000);
}

export const toast = {
  success: (text: string) => push("success", text),
  error: (text: string) => push("error", text),
};

export function Toaster() {
  const items = useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => toasts,
    () => toasts,
  );
  return (
    <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex flex-col gap-2" role="status" aria-live="polite">
      {items.map((t) => (
        <div
          key={t.id}
          className={cn(
            "pointer-events-auto flex max-w-sm items-start gap-2 rounded-lg border px-3 py-2 text-sm shadow-lg",
            t.kind === "success" ? "border-emerald-600/30 bg-emerald-50 text-emerald-900" : "border-red-600/30 bg-red-50 text-red-900",
          )}
        >
          {t.kind === "success" ? <CheckCircle2Icon className="mt-0.5 size-4 shrink-0" /> : <XCircleIcon className="mt-0.5 size-4 shrink-0" />}
          <span>{t.text}</span>
        </div>
      ))}
    </div>
  );
}
