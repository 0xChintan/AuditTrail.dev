import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Sidebar } from "@/components/at/sidebar";
import { Toaster } from "@/components/at/toast";
import { headers } from "next/headers";
import { api, operator } from "@/lib/api";
import type { Tenant } from "@/lib/types";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: { default: "AuditTrail", template: "%s · AuditTrail" },
  description: "Tamper-evident audit ledger for humans and AI agents",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // Tenant names are only for signed-in operators (public pages like /verify share this layout).
  const authed = (await headers()).get("x-at-authed") === "1";
  const tenants = authed ? await api<{ tenants: Tenant[] }>("/v1/admin/tenants").then((r) => r.tenants).catch(() => [] as Tenant[]) : [];
  const who = authed ? await operator() : null;
  const sso = Boolean(process.env.OIDC_ISSUER);
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="flex min-h-full bg-zinc-50 font-sans text-foreground dark:bg-background">
        <Sidebar tenants={[...tenants].reverse().map((t) => ({ id: t.id, name: t.name, legal_hold: t.legal_hold }))} operator={who} sso={sso && authed} />
        <main className="min-w-0 flex-1">{children}</main>
        <Toaster />
      </body>
    </html>
  );
}
