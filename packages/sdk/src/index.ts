export { AuditTrail, AuditTrailError, type AuditTrailOptions, type AuditEvent, type Receipt, type Metric, type Outcome } from "./client.js";
export { MemorySpool, type Spool, type SpooledEvent } from "./queue.js";
export { DEFAULT_SECRET_PATTERNS, DEFAULT_SECRET_KEYS, redactValue, redactString, type RedactionOptions, type SecretPattern } from "./redact.js";
export { verifyRecord, verifyBundle, v2 } from "@audittrail/core";
