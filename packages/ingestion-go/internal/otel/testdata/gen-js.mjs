// OpenTelemetry JS SDK -> OTLP/HTTP JSON. Fixed ids + times so the trace is
// comparable with the Python SDK fixture.
import { BasicTracerProvider, BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { resourceFromAttributes } from "@opentelemetry/resources";
import { trace, context, SpanStatusCode } from "@opentelemetry/api";
const ids = { trace: "4bf92f3577b34da6a3ce929d0e0e4736", spans: ["00f067aa0ba902b7", "1111111111111111", "2222222222222222"] };
let n = 0;
const idGenerator = { generateTraceId: () => ids.trace, generateSpanId: () => ids.spans[n++] };
const provider = new BasicTracerProvider({
  idGenerator,
  resource: resourceFromAttributes({ "service.name": "support-bot", "service.version": "3.2.0" }),
  spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter({ url: "http://127.0.0.1:" + process.argv[2] + "/v1/traces" }))],
});
const tr = provider.getTracer("fixture", "1.0.0");
const T0 = 1790000000000; // ms
const agent = tr.startSpan("invoke_agent support-agent", { startTime: T0, attributes: {
  "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "support-agent", "gen_ai.agent.id": "agt_42",
  "gen_ai.provider.name": "anthropic", "gen_ai.request.model": "claude-sonnet-5", "gen_ai.conversation.id": "conv_9", "user.id": "alice@example.com",
  "gen_ai.usage.input_tokens": 1200, "gen_ai.usage.output_tokens": 340 } });
const ctx = trace.setSpan(context.active(), agent);
const t1 = tr.startSpan("execute_tool lookup_order", { startTime: T0 + 100, attributes: {
  "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup_order", "gen_ai.tool.call.id": "call_1", "gen_ai.tool.type": "function",
  "gen_ai.agent.id": "agt_42", "gen_ai.conversation.id": "conv_9", "user.id": "alice@example.com" } }, ctx);
t1.setStatus({ code: SpanStatusCode.OK });
t1.end(T0 + 250);
const t2 = tr.startSpan("execute_tool refund_order", { startTime: T0 + 300, attributes: {
  "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund_order", "gen_ai.tool.call.id": "call_2", "gen_ai.tool.type": "function",
  "gen_ai.agent.id": "agt_42", "gen_ai.conversation.id": "conv_9", "user.id": "alice@example.com", "error.type": "PermissionDenied" } }, ctx);
t2.setStatus({ code: SpanStatusCode.ERROR, message: "refund requires approval" });
t2.end(T0 + 400);
agent.end(T0 + 900);
await provider.forceFlush();
await provider.shutdown();
