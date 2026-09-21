"""Credential-free OpenTelemetry adapter for boundary decision evidence."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


_LAB_SPEC = importlib.util.spec_from_file_location("trust_boundary_lab", Path(__file__).with_name("lab.py"))
assert _LAB_SPEC and _LAB_SPEC.loader
_LAB = importlib.util.module_from_spec(_LAB_SPEC)
sys.modules[_LAB_SPEC.name] = _LAB
_LAB_SPEC.loader.exec_module(_LAB)
BoundaryDecision = _LAB.BoundaryDecision
evaluate_controls = _LAB.evaluate_controls


ALLOWED_ATTRIBUTES = {
    "boundary.id",
    "boundary.decision",
    "boundary.reason",
    "boundary.operation",
    "boundary.policy_version",
    "boundary.evidence_count",
}


def export_decisions(decisions: list[BoundaryDecision]):
    """Export bounded attributes; raw content, identity, and resource IDs stay out."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("agent-security.trust-boundaries")
    for decision in decisions:
        with tracer.start_as_current_span("agent.boundary.decision") as span:
            attributes = {
                "boundary.id": decision.boundary_id,
                "boundary.decision": "allow" if decision.allowed else "deny",
                "boundary.reason": decision.reason,
                "boundary.operation": decision.operation,
                "boundary.policy_version": decision.policy_version,
                "boundary.evidence_count": decision.evidence_count,
            }
            for key, value in attributes.items():
                span.set_attribute(key, value)
    provider.shutdown()
    return exporter.get_finished_spans()


def demo():
    report, decisions = evaluate_controls()
    spans = export_decisions(decisions)
    assert len(spans) == len(decisions)
    assert all(set(span.attributes) == ALLOWED_ATTRIBUTES for span in spans)
    rendered = repr([dict(span.attributes) for span in spans])
    assert "user:7" not in rendered and "case:42" not in rendered and "synthetic-content" not in rendered
    return report, spans


if __name__ == "__main__":
    report, spans = demo()
    print({"report": report, "exported_spans": len(spans)})
