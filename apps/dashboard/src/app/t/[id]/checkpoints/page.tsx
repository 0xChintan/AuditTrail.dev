import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import { fmtTime, shortHash } from "@/lib/format";
import type { Checkpoint } from "@/lib/types";
import { cn } from "@/lib/utils";

export const dynamic = "force-dynamic";

const tone: Record<string, string> = {
  anchored: "bg-emerald-50 text-emerald-700 ring-emerald-600/20",
  pending: "bg-sky-50 text-sky-700 ring-sky-600/20",
  failed: "bg-red-50 text-red-700 ring-red-600/20",
  disabled: "bg-muted text-muted-foreground ring-border",
};

export default async function Checkpoints({ params }: PageProps<"/t/[id]/checkpoints">) {
  const { id } = await params;
  const { checkpoints } = await api<{ checkpoints: Checkpoint[] }>("/v1/checkpoints?limit=200", { tenant: id });
  return (
    <div className="space-y-4">
      <p className="max-w-3xl text-sm text-muted-foreground">
        The checkpoint worker periodically signs an RFC 6962 Merkle root over each new run of records and has it time-stamped by an
        independent RFC 3161 authority. After that, nobody, including whoever operates this ledger, can rewrite those records without the
        mismatch being provable against the authority&apos;s signature.
      </p>
      <Card className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Records</TableHead>
              <TableHead>Merkle root</TableHead>
              <TableHead>Head hash</TableHead>
              <TableHead>Signed by</TableHead>
              <TableHead>External anchor</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {checkpoints.map((c) => (
              <TableRow key={c.id}>
                <TableCell className="tabular-nums">seq {c.first_seq}–{c.last_seq} <span className="text-muted-foreground">({c.row_count})</span></TableCell>
                <TableCell className="font-mono text-xs">{shortHash(c.merkle_root, 16)}</TableCell>
                <TableCell className="font-mono text-xs">{shortHash(c.head_hash, 12)}</TableCell>
                <TableCell className="font-mono text-xs">{c.key_id}</TableCell>
                <TableCell>
                  <span className={cn("rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", tone[c.anchor_status])}>{c.anchor_status}</span>
                  {c.anchor_authority && <div className="mt-0.5 text-[11px] text-muted-foreground">{c.anchor_authority.replace(/ \(.*\)$/, "")} · {c.anchored_at && fmtTime(c.anchored_at)}</div>}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{fmtTime(c.created_at)}</TableCell>
              </TableRow>
            ))}
            {checkpoints.length === 0 && (
              <TableRow><TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">No checkpoints yet. Run <code>audittrail-worker</code>.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}
