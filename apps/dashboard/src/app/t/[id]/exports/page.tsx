import { ExportCard } from "@/components/at/export-card";
import { CodeBlock } from "@/components/at/copy";
import { api } from "@/lib/api";
import type { Template, Tenant } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function Exports({ params }: PageProps<"/t/[id]/exports">) {
  const { id } = await params;
  const [{ templates }, t] = await Promise.all([api<{ templates: Template[] }>("/v1/templates"), api<Tenant>(`/v1/admin/tenants/${id}`)]);
  return (
    <div className="space-y-6">
      <p className="max-w-3xl text-sm text-muted-foreground">
        Each export pulls the records in range (widened to whole checkpoints), the covering signed checkpoints and their RFC 3161 anchor
        proofs, and labels every column with the clause it evidences. The PDF is for reviewers; the evidence bundle is for independent
        verification.
      </p>
      <div className="grid gap-4 xl:grid-cols-3">
        {templates.map((tpl) => (
          <ExportCard key={tpl.id} t={tpl} tenant={id} retentionDays={t.retention_days} />
        ))}
      </div>
      <div className="max-w-3xl space-y-2">
        <h2 className="text-sm font-semibold">Verify an evidence bundle independently</h2>
        <p className="text-sm text-muted-foreground">Auditors don&apos;t need access to this system. They can use the CLI, or the browser portal under <b>Verify evidence</b>.</p>
        <CodeBlock code={`audittrail-verify --tsa-roots freetsa-cacert.pem --require-anchors audittrail-*.bundle.json`} />
      </div>
    </div>
  );
}
