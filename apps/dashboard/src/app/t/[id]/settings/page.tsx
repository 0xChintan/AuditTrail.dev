import { SettingsForm } from "@/components/at/settings-form";
import { api } from "@/lib/api";
import type { Tenant } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function Settings({ params }: PageProps<"/t/[id]/settings">) {
  const { id } = await params;
  const [t, { purges }] = await Promise.all([
    api<Tenant>(`/v1/admin/tenants/${id}`),
    api<{ purges: { purged_through_seq: number; rows_deleted: number; purged_at: string; performed_by: string }[] }>("/v1/purges", { tenant: id }),
  ]);
  return <SettingsForm key={`${t.legal_hold}-${t.retention_days}`} t={t} purges={purges} />;
}
