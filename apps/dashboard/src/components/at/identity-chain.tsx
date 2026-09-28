import { BotIcon, CornerDownRightIcon, FootprintsIcon, NetworkIcon, UserIcon, WrenchIcon, MessageSquareIcon, CircleDotIcon } from "lucide-react";
import type { DelegationFrame } from "@audittrail/core";

const icons: Record<string, React.ComponentType<{ className?: string }>> = {
  human: UserIcon,
  agent: BotIcon,
  subagent: BotIcon,
  mcp_session: NetworkIcon,
  turn: FootprintsIcon,
  tool_call: WrenchIcon,
  sampling_request: MessageSquareIcon,
  elicitation_request: UserIcon,
};

function short(id: string) {
  const parts = id.split(":");
  return parts.length > 2 ? parts.slice(-2).join(":") : id;
}

/** Visualizes the delegation chain: who asked whom to do what. */
export function IdentityChain({ chain }: { chain: DelegationFrame[] | null }) {
  if (!chain?.length) return <p className="text-sm text-muted-foreground">No delegation chain recorded.</p>;
  return (
    <ol className="space-y-1">
      {chain.map((f, i) => {
        const Icon = icons[f.type] ?? CircleDotIcon;
        const extra = [f.model && `model ${String(f.model)}`, f.tool && `tool ${String(f.tool)}`, f.server && `server ${String(f.server)}`, f.method && String(f.method)]
          .filter(Boolean)
          .join(" · ");
        return (
          <li key={i} className="flex items-start gap-2" style={{ paddingLeft: i * 12 }}>
            {i > 0 && <CornerDownRightIcon className="mt-0.5 size-3.5 shrink-0 text-muted-foreground/60" />}
            <Icon className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" />
            <div className="min-w-0 text-xs">
              <span className="font-medium">{f.type}</span> <span className="font-mono break-all">{short(String(f.id))}</span>
              {f.source ? <span className="ml-1 rounded bg-muted px-1 text-[10px] text-muted-foreground">{String(f.source)}</span> : null}
              {extra && <div className="text-[11px] text-muted-foreground">{extra}</div>}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
