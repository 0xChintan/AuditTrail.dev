import { PageHeader } from "@/components/at/page-header";
import { VerifyPortal } from "@/components/at/verify-portal";

export const metadata = { title: "Verify evidence" };

export default function VerifyPage() {
  return (
    <div>
      <PageHeader
        title="Verify evidence"
        description="Paste a record, an inclusion proof or an exported bundle, and check its hash, chain link and signatures yourself in the browser, without trusting this system."
      />
      <div className="px-8 py-6"><VerifyPortal /></div>
    </div>
  );
}
