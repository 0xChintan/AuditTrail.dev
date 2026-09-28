// Signed v2 ingest for the shell demos (v1 unsigned POST /v1/events is gone).
//   node scripts/lib/ingest-v2.mjs <at2_key> <from> <to> <kind>
// kind: payments (tamper-demo) | reads (retention-demo)
import { AuditTrail } from "../../packages/sdk/dist/index.js";

const [key, from, to, kind = "payments"] = process.argv.slice(2);
const baseUrl = process.env.API ?? "http://localhost:8080";
const at = new AuditTrail({ apiKey: key, baseUrl, agent: { id: kind === "reads" ? "etl-agent" : "payments-agent" }, failMode: "closed" });
for (let i = Number(from); i <= Number(to); i++) {
  if (kind === "reads") {
    await at.record({ action: "record.read", resource: `patient/${i}`, outcome: "allowed" });
  } else {
    await at.record({
      principal: { id: "alice", type: "human" },
      model: { id: "claude-opus-5-5" },
      action: "payment.transfer",
      resource: `account/${i}`,
      outcome: i % 7 === 0 ? "denied" : "allowed",
      payload: { amount_eur: i * 100 },
    });
  }
}
await at.close();
