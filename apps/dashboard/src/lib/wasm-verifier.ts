"use client";

/**
 * Loads the offline Go verifier compiled to WebAssembly (public/verifier/).
 * It is the same code as the audittrail-verify CLI, it performs no network
 * I/O, and everything is computed in this browser.
 */
type VerifyFn = (bundleJSON: string, optionsJSON: string) => string;

let loading: Promise<VerifyFn> | null = null;

export interface WasmOptions {
  log_keys?: string[];
  witnesses?: string[];
  quorum?: number;
  max_age_seconds?: number;
  require_covered?: boolean;
  others?: string[];
}

export interface WasmReport {
  ok: boolean;
  error?: string;
  origin: string;
  trust: "pinned" | "UNPINNED";
  first_seq: number;
  last_seq: number;
  events: number;
  tree_heads: number;
  latest_head_size: number;
  witnessed_by: string[] | null;
  anchored_at?: string;
  checks: Record<string, { status: "pass" | "fail" | "warn" | "skip"; detail: string }>;
  failures: { invariant: string; seq?: number; tree_size?: number; detail: string }[];
  warnings: { invariant: string; seq?: number; tree_size?: number; detail: string }[];
  tampered_seqs: number[];
}

export function loadVerifier(): Promise<VerifyFn> {
  if (loading) return loading;
  loading = (async () => {
    const g = globalThis as unknown as { Go?: new () => { importObject: WebAssembly.Imports; run(i: WebAssembly.Instance): Promise<void> }; auditTrailVerify?: VerifyFn; auditTrailVerifierReady?: boolean };
    if (!g.Go) {
      await new Promise<void>((resolve, reject) => {
        const s = document.createElement("script");
        s.src = "/verifier/wasm_exec.js";
        s.onload = () => resolve();
        s.onerror = () => reject(new Error("could not load wasm_exec.js"));
        document.head.appendChild(s);
      });
    }
    const go = new g.Go!();
    const res = await fetch("/verifier/verify.wasm");
    const { instance } = await WebAssembly.instantiate(await res.arrayBuffer(), go.importObject);
    void go.run(instance);
    for (let i = 0; i < 200 && !g.auditTrailVerifierReady; i++) await new Promise((r) => setTimeout(r, 10));
    if (!g.auditTrailVerify) throw new Error("verifier did not start");
    return g.auditTrailVerify;
  })();
  return loading;
}

export async function verifyBundleWasm(bundleJSON: string, opts: WasmOptions): Promise<WasmReport> {
  const fn = await loadVerifier();
  return JSON.parse(fn(bundleJSON, JSON.stringify(opts)));
}
