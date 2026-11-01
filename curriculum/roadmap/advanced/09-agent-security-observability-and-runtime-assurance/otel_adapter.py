"""Real OpenTelemetry Python SDK adapter for the Advanced 09 lab.

OpenTelemetry transports observations; it does not make an event authoritative.
The trusted application still binds identity and versions, applies an allowlist,
and runs the deterministic monitors in ``runtime_assurance``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import runtime_assurance as lab


@dataclass(frozen=True)
class OTelCapture:
    exporter: InMemorySpanExporter
    provider: TracerProvider
    authority_by_event_id: Mapping[str, lab.Authority]

    def spans(self) -> tuple[ReadableSpan, ...]:
        self.provider.force_flush()
        return self.exporter.get_finished_spans()

    def shutdown(self) -> None:
        self.provider.shutdown()


def create_capture(
    service_name: str = "advanced-09-runtime-assurance",
    authority_by_event_id: Mapping[str, lab.Authority] | None = None,
) -> OTelCapture:
    exporter = InMemorySpanExporter(max_spans=64)
    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: service_name}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return OTelCapture(exporter, provider, dict(authority_by_event_id or {}))


def emit_case(case: lab.Case) -> tuple[OTelCapture, lab.RunBinding]:
    """Emit low-cardinality, redacted spans for one deterministic fixture."""
    binding, events = lab.events_for(case)
    # This application-owned map stands in for authenticated producer identity.
    # It is deliberately kept outside the span attributes.
    authority_by_event_id = {event.event_id: event.authority for event in events}
    capture = create_capture(authority_by_event_id=authority_by_event_id)
    tracer = capture.provider.get_tracer("agent-security.course.advanced-09", "1.0")
    for event in events:
        with tracer.start_as_current_span(f"assurance {event.kind.value}") as span:
            span.set_attributes({
                "security.event.id": event.event_id,
                "security.event.sequence": event.sequence,
                "security.event.emitted_at_ms": event.emitted_at_ms,
                "security.event.kind": event.kind.value,
                "security.event.source": event.source,
                "security.event.claimed_authority": event.authority.value,
                "security.binding.digest": event.binding_digest,
                "security.tenant.id": event.tenant_id,
                "security.subject.id": event.subject_id,
                "security.operation.id": event.operation_id,
                "security.reason_code": event.reason_code,
                "security.evidence.ids": event.evidence_ids,
                **{f"security.attribute.{key}": value for key, value in event.attributes.items()},
            })
    return capture, binding


def spans_to_events(
    spans: Iterable[ReadableSpan],
    authority_by_event_id: Mapping[str, lab.Authority] | None = None,
) -> tuple[lab.TraceEvent, ...]:
    """Admit the schema while deriving authority outside span-controlled data."""
    authority_by_event_id = authority_by_event_id or {}
    result: list[lab.TraceEvent] = []
    for span in spans:
        attributes = dict(span.attributes or {})
        safe_attributes = {
            key.removeprefix("security.attribute."): value
            for key, value in attributes.items()
            if key.startswith("security.attribute.")
        }
        evidence = attributes.get("security.evidence.ids", ())
        if isinstance(evidence, str):
            evidence = (evidence,)
        event_id = str(attributes["security.event.id"])
        result.append(lab.TraceEvent(
            event_id=event_id,
            sequence=int(attributes["security.event.sequence"]),
            emitted_at_ms=int(attributes["security.event.emitted_at_ms"]),
            kind=lab.EventKind(str(attributes["security.event.kind"])),
            source=str(attributes["security.event.source"]),
            authority=authority_by_event_id.get(event_id, lab.Authority.UNTRUSTED),
            binding_digest=str(attributes["security.binding.digest"]),
            tenant_id=str(attributes["security.tenant.id"]),
            subject_id=str(attributes["security.subject.id"]),
            operation_id=str(attributes["security.operation.id"]),
            reason_code=str(attributes["security.reason_code"]),
            evidence_ids=tuple(str(item) for item in evidence),
            attributes=safe_attributes,
        ))
    return tuple(sorted(result, key=lambda item: (item.sequence, item.event_id)))


def run_adapter(case_id: str = "valid-refund") -> lab.CaseAssessment:
    case = next(item for item in lab.course_cases() if item.case_id == case_id)
    capture, binding = emit_case(case)
    try:
        events = spans_to_events(capture.spans(), capture.authority_by_event_id)
        return lab.assess_case(case, binding, events)
    finally:
        capture.shutdown()


if __name__ == "__main__":
    assessment = run_adapter()
    print({"case": assessment.case_id, "state": assessment.state.value, "events": len(assessment.admitted_event_ids)})
