import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Sidebar } from "@/components/at/sidebar";
import { Toaster } from "@/components/at/toast";
import { api } from "@/lib/api";
import type { Tenant } from "@/lib/types";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: { default: "AuditTrail", template: "%s · AuditTrail" },
  description: "Tamper-evident audit ledger for humans and AI agents",
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  const tenants = await api<{ tenants: Tenant[] }>("/v1/admin/tenants").then((r) => r.tenants).catch(() => [] as Tenant[]);
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="flex min-h-full bg-zinc-50 font-sans text-foreground dark:bg-background">
        <Sidebar tenants={[...tenants].reverse().map((t) => ({ id: t.id, name: t.name, legal_hold: t.legal_hold }))} />
        <main className="min-w-0 flex-1">{children}</main>
        <Toaster />
      </body>
    </html>
  );
}
