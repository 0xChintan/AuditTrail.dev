# OpenTelemetry Python SDK -> OTLP/HTTP protobuf. Same logical trace, ids and
# times as gen-js.mjs.
import sys
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.id_generator import IdGenerator
from opentelemetry.sdk.resources import Resource
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.trace import Status, StatusCode

class Fixed(IdGenerator):
    spans = [0x00f067aa0ba902b7, 0x1111111111111111, 0x2222222222222222]
    def generate_trace_id(self): return 0x4bf92f3577b34da6a3ce929d0e0e4736
    def generate_span_id(self): return self.spans.pop(0)

tp = TracerProvider(id_generator=Fixed(), resource=Resource.create({"service.name": "support-bot", "service.version": "3.2.0"}))
tp.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"http://127.0.0.1:{sys.argv[1]}/v1/traces")))
tr = tp.get_tracer("fixture", "1.0.0")
T0 = 1790000000000 * 1_000_000  # ns
common = {"gen_ai.agent.id": "agt_42", "gen_ai.conversation.id": "conv_9", "user.id": "alice@example.com"}
agent = tr.start_span("invoke_agent support-agent", start_time=T0, attributes={
    "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "support-agent", "gen_ai.provider.name": "anthropic",
    "gen_ai.request.model": "claude-sonnet-5", "gen_ai.usage.input_tokens": 1200, "gen_ai.usage.output_tokens": 340, **common})
ctx = trace.set_span_in_context(agent)
t1 = tr.start_span("execute_tool lookup_order", context=ctx, start_time=T0 + 100_000_000, attributes={
    "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup_order", "gen_ai.tool.call.id": "call_1", "gen_ai.tool.type": "function", **common})
t1.set_status(Status(StatusCode.OK)); t1.end(end_time=T0 + 250_000_000)
t2 = tr.start_span("execute_tool refund_order", context=ctx, start_time=T0 + 300_000_000, attributes={
    "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "refund_order", "gen_ai.tool.call.id": "call_2", "gen_ai.tool.type": "function",
    "error.type": "PermissionDenied", **common})
t2.set_status(Status(StatusCode.ERROR, "refund requires approval")); t2.end(end_time=T0 + 400_000_000)
agent.end(end_time=T0 + 900_000_000)
tp.shutdown()
