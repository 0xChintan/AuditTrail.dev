# Performance and chaos results

Measured on 2026-09-28 on a single Apple-silicon laptop: local Postgres 18, one API process, one tenant. This is the worst case for a hash chain, because every write contends for the same chain head. Spotlight indexing was running during the k6 runs, so treat these numbers as a floor.

## Ingest throughput (`POST /v2/events`, signed requests, full validation)

| Scenario | Tool | Events | Result |
|---|---|---|---|
| Group commit (batch ≤ 256) | `bin/stress -n 10000 -c 256 -spawn ./bin/api` | 10,000 | **6,337 events/s**, 0 gaps, 0 dupes |
| Group commit disabled (batch 1) | same, `-batch 1` | 10,000 | 2,381 events/s: group commit is **2.7×** faster |
| k6, 64 VUs, pre-signed requests | `tests/load/ingest.js` | 20,000 | **4,783 req/s**; seal latency p50 13.0 ms · p95 15.6 ms · p99 24.8 ms · max 47 ms; 0 lost |

A tenant's throughput is bounded by one row lock per batch (the chain head), not by request count, and grows with batch size. Different tenants don't contend with each other.

## Chaos

| Fault injected | Result |
|---|---|
| `kill -9` of the API at 40% and at 75% of a 10k burst (1,024 requests in flight) | Clients retried the same bodies; 10,001 rows, 0 gaps, 0 duplicates, every hash valid |
| Postgres restarted (`pg_ctl restart -m fast`) during a 20k k6 run | 64 in-flight requests failed and were retried; **0 events lost**; 20,001 rows verified offline |
| Network: delays, responses dropped after commit, duplicated requests, 503s, then **60 min offline** (SDK with a disk spool) | See `scripts/chaos-sdk-offline.mjs` and PROGRESS.md: every event arrives exactly once, in order; duplicated requests are rejected as nonce replays |
| MCP sidecar `SIGKILL` | Monitor seals `audittrail.monitor/sidecar_silent`; a cleanly stopped sidecar is not flagged |

## Reproduce

```sh
cd packages/ingestion-go
./bin/stress -n 10000 -c 256 -spawn ./bin/api -kill-at 0.4
read TID KEY < <(./bin/loadgen -n 20000 -out /tmp/load.jsonl)
k6 run -e FILE=/tmp/load.jsonl -e KEY=$KEY -e VUS=64 ../../tests/load/ingest.js
```

## Shared rate limiter overhead

Tenant rate limits are enforced across instances through Postgres (leased token batches). Same machine, 10k writers, 128 in flight, 3 runs each: **6,073 events/s shared vs 6,131 local** (about 1%).
