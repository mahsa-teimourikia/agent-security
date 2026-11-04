"""Real OpenTelemetry SDK adapter for minimized architecture decision spans."""
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import enterprise_architecture as arch


class DecisionTelemetry:
    def __init__(self):
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("course.enterprise-architecture")

    def emit(self, receipt: arch.DecisionReceipt) -> None:
        with self.tracer.start_as_current_span("agent.boundary.decision") as span:
            span.set_attribute("agent.request.id", receipt.request_id)
            span.set_attribute("agent.flow.id", receipt.flow_id)
            span.set_attribute("agent.tenant", receipt.tenant)
            span.set_attribute("agent.capability", receipt.capability)
            span.set_attribute("agent.architecture.version", receipt.architecture_version)
            span.set_attribute("agent.policy.version", receipt.policy_version)
            span.set_attribute("agent.decision", receipt.state.value)
            span.set_attribute("agent.reason", receipt.reason)
            span.set_attribute("agent.receipt.digest", arch.digest(receipt.proof))

    def finished(self):
        return self.exporter.get_finished_spans()
