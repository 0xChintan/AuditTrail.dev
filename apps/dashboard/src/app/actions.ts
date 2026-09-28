"use server";

import { revalidatePath } from "next/cache";
import { api, ApiError } from "@/lib/api";
import type { ApiKey, Tenant } from "@/lib/types";

export type Result<T> = { ok: true; data: T } | { ok: false; error: string };

async function run<T>(fn: () => Promise<T>, revalidate?: string): Promise<Result<T>> {
  try {
    const data = await fn();
    if (revalidate) revalidatePath(revalidate, "layout");
    return { ok: true, data };
  } catch (e) {
    return { ok: false, error: e instanceof ApiError ? e.message : String(e) };
  }
}

export async function createTenant(input: { name: string; retention_days: number }) {
  return run(
    () => api<{ tenant: Tenant; api_key: string }>("/v1/admin/tenants", { method: "POST", body: input }),
    "/",
  );
}

export async function createApiKey(tenantId: string, name: string) {
  return run(
    () => api<{ api_key: string; api_key_info: ApiKey }>(`/v1/admin/tenants/${tenantId}/api-keys`, { method: "POST", body: { name } }),
    `/t/${tenantId}`,
  );
}

export async function revokeApiKey(tenantId: string, keyId: string) {
  return run(() => api<void>(`/v1/admin/tenants/${tenantId}/api-keys/${keyId}`, { method: "DELETE" }), `/t/${tenantId}`);
}

export async function rotateSigningKey(tenantId: string) {
  return run(() => api<{ key_id: string }>(`/v1/admin/tenants/${tenantId}/signing-keys/rotate`, { method: "POST" }), `/t/${tenantId}`);
}

export async function updateSettings(
  tenantId: string,
  patch: Partial<Pick<Tenant, "name" | "retention_days" | "legal_hold" | "legal_hold_reason" | "rate_limit_rps" | "rate_limit_burst">>,
) {
  return run(() => api<Tenant>(`/v1/admin/tenants/${tenantId}`, { method: "PATCH", body: patch }), `/t/${tenantId}`);
}
