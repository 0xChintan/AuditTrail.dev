// k6 load test for POST /v2/events using pre-signed requests
// (see cmd/loadgen). Each iteration sends one event, retrying with its
// alternate signed attempts on network errors / 5xx / 429.
//   k6 run -e FILE=/tmp/load.jsonl -e KEY=at2_… -e VUS=64 tests/load/ingest.js
import http from "k6/http";
import { check, sleep } from "k6";
import { SharedArray } from "k6/data";
import exec from "k6/execution";
import { Counter, Trend } from "k6/metrics";

const events = new SharedArray("events", () => open(__ENV.FILE).trim().split("\n").map((l) => JSON.parse(l)));
const API = __ENV.API || "http://localhost:8080";
const retries = new Counter("event_retries");
const lost = new Counter("events_lost");
const sealed = new Trend("seal_latency", true);

export const options = {
  scenarios: {
    ingest: { executor: "shared-iterations", vus: Number(__ENV.VUS || 64), iterations: events.length, maxDuration: "4m" },
  },
  thresholds: { events_lost: ["count==0"], checks: ["rate==1.0"] },
};

export default function () {
  const ev = events[exec.scenario.iterationInTest];
  let ok = false;
  for (const t of ev.tries) {
    const res = http.post(`${API}/v2/events`, ev.body, {
      headers: { "content-type": "application/json", authorization: `Bearer ${__ENV.KEY}`, "x-at-timestamp": t.ts, "x-at-nonce": t.nonce, "x-at-signature": t.sig },
      timeout: "20s",
    });
    if (res.status === 202 || res.status === 200) {
      sealed.add(res.timings.duration);
      ok = true;
      break;
    }
    retries.add(1);
    sleep(2); // back off: survives a few seconds of database/API outage
  }
  if (!ok) lost.add(1);
  check(ok, { "event sealed": (v) => v });
}
