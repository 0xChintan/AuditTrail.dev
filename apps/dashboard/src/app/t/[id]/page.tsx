import { ActivityIcon, CheckIcon, OctagonXIcon, ShieldBanIcon, TimerIcon } from "lucide-react";
import { Timeline } from "@/components/at/timeline";
import { VerifyStatus } from "@/components/at/verify-status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { num, shortHash } from "@/lib/format";
import type { Stats } from "@/lib/types";

export const dynamic = "force-dynamic";

function Stat({ label, value, icon: Icon, tone }: { label: string; value: number; icon: React.ComponentType<{ className?: string }>; tone: string }) {
  return (
    <Card className="gap-1 p-4">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        {label} <Icon className={`size-4 ${tone}`} />
      </div>
      <div className="text-2xl font-semibold tabular-nums tracking-tight">{num(value)}</div>
    </Card>
  );
}

export default async function Activity({ params }: PageProps<"/t/[id]">) {
  const { id } = await params;
  const s = await api<Stats>("/v1/stats", { tenant: id });
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Stat label="Records" value={s.total} icon={ActivityIcon} tone="text-foreground" />
        <Stat label="Allowed" value={s.by_outcome.allowed} icon={CheckIcon} tone="text-emerald-600" />
        <Stat label="Denied / blocked" value={s.by_outcome.denied} icon={ShieldBanIcon} tone="text-amber-600" />
        <Stat label="Errors" value={s.by_outcome.error} icon={OctagonXIcon} tone="text-red-600" />
        <Stat label="Last 24 hours" value={s.last_24h} icon={TimerIcon} tone="text-muted-foreground" />
      </div>
      <div className="grid gap-6 xl:grid-cols-[1fr_320px]">
        <div className="min-w-0">
          <h2 className="mb-2 text-sm font-semibold">Agent activity</h2>
          <Timeline tenant={id} agents={s.top_agents.map((a) => a.name)} />
        </div>
        <div className="space-y-4">
          <Card>
            <CardHeader><CardTitle className="text-sm">Chain verification</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              <VerifyStatus tenant={id} />
              <div className="border-t pt-2 text-[11px] text-muted-foreground">
                head <span className="font-mono">{shortHash(s.head_hash, 16)}</span> at seq {s.head_seq}
                {s.oldest_seq > 1 && <> · rows before seq {s.oldest_seq} purged under retention</>}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle className="text-sm">Most active agents</CardTitle></CardHeader>
            <CardContent className="space-y-1.5">
              {s.top_agents.map((a) => (
                <div key={a.name} className="flex items-center gap-2 text-xs">
                  <div className="min-w-0 flex-1 truncate">{a.name}</div>
                  <div className="h-1.5 w-20 overflow-hidden rounded-full bg-muted">
                    <div className="h-full bg-foreground/70" style={{ width: `${(a.count / Math.max(1, s.top_agents[0]!.count)) * 100}%` }} />
                  </div>
                  <div className="w-10 text-right tabular-nums text-muted-foreground">{num(a.count)}</div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
