import { KeysPanel } from "@/components/at/keys-panel";
import { api } from "@/lib/api";
import type { ApiKey, PublicKey } from "@/lib/types";

export const dynamic = "force-dynamic";

export default async function Keys({ params }: PageProps<"/t/[id]/keys">) {
  const { id } = await params;
  const [{ api_keys }, { keys }] = await Promise.all([
    api<{ api_keys: ApiKey[] }>(`/v1/admin/tenants/${id}/api-keys`),
    api<{ keys: PublicKey[] }>(`/v1/tenants/${id}/public-keys`),
  ]);
  return <KeysPanel tenant={id} keys={api_keys} signing={keys} />;
}
