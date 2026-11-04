"""Real OpenTelemetry SDK adapter for minimized capstone decision evidence."""
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import production_capstone as core


class CapstoneTelemetry:
    def __init__(self):
        self.exporter = InMemorySpanExporter()
        self.provider = TracerProvider()
        self.provider.add_span_processor(SimpleSpanProcessor(self.exporter))
        self.tracer = self.provider.get_tracer("course.production-capstone")

    def emit(self, receipt: core.DecisionReceipt) -> None:
        with self.tracer.start_as_current_span("agent.capstone.decision") as span:
            span.set_attribute("agent.request.id", receipt.request_id)
            span.set_attribute("agent.operation", receipt.operation)
            span.set_attribute("agent.logical_operation.id", receipt.logical_operation_id)
            span.set_attribute("agent.policy.version", receipt.policy_version)
            span.set_attribute("agent.control.epoch", receipt.control_epoch)
            span.set_attribute("agent.decision", receipt.decision.value)
            span.set_attribute("agent.reason", receipt.reason)
            span.set_attribute("agent.effect.id", receipt.effect_id)
            span.set_attribute("agent.evidence.count", len(receipt.evidence_ids))

    def finished(self):
        return self.exporter.get_finished_spans()
