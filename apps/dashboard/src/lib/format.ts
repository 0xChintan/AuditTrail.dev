export function shortHash(h: string | null | undefined, n = 10): string {
  return h ? `${h.slice(0, n)}…` : "—";
}

export function timeAgo(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

export function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z").replace("Z", " UTC");
}

export function num(n: number): string {
  return new Intl.NumberFormat("en-US").format(n);
}
