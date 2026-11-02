"""Real OpenTelemetry Python SDK adapter for Enterprise 03.

Telemetry is evidence input, not authority. Transport-authenticated producer and
tenant bindings are supplied by the application; span attributes remain
untrusted observations and never approve containment.
"""
from __future__ import annotations

from dataclasses import asdict

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.trace.id_generator import IdGenerator

import incident_response as core


class FixedIdGenerator(IdGenerator):
    """Deterministic IDs for a credential-free teaching fixture."""

    def generate_span_id(self) -> int:
        return 0x2222222222222222

    def generate_trace_id(self) -> int:
        return 0x11111111111111111111111111111111


def capture_effect_span() -> object:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(
        resource=Resource.create({"service.name": "agent-effect-gateway"}),
        id_generator=FixedIdGenerator(),
        shutdown_on_exit=False,
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("enterprise-03-course", "1.0")
    with tracer.start_as_current_span("agent.effect", start_time=100_000_000_000) as span:
        span.set_attribute("agent.run_id", "run:north:42")
        span.set_attribute("agent.id", "support-7")
        span.set_attribute("agent.declared_tenant", "attacker-controlled-value")
        span.set_attribute("security.principal_digest", core.digest("principal:north:alice")[:16])
        span.set_attribute("tool.name", "http.post")
        span.set_attribute("server.address", "collector.evil")
        span.set_attribute("security.policy_decision", "allow")
        span.set_attribute("operation.id", "action:42")
        span.set_attribute("operation.outcome", "committed")
        span.set_attribute("workflow.checkpoint_id", "checkpoint:north:42")
    provider.force_flush()
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    provider.shutdown()
    return spans[0]


def signal_from_span(span: object, *, producer: core.Producer, trusted_tenant: str,
                     event_id: str, occurred_at: int) -> core.RawSignal:
    attributes = dict(span.attributes)
    trace_id = f"{span.context.trace_id:032x}"
    raw = core.RawSignal(
        event_id=event_id,
        producer_id=producer.producer_id,
        tenant=trusted_tenant,
        trace_id=trace_id,
        run_id=str(attributes.get("agent.run_id", "")),
        agent_id=str(attributes.get("agent.id", "")),
        kind=core.SignalKind.EFFECT_RESULT,
        occurred_at=occurred_at,
        principal_digest=str(attributes.get("security.principal_digest", "")),
        tool=str(attributes.get("tool.name", "")),
        destination=str(attributes.get("server.address", "")),
        policy_decision=str(attributes.get("security.policy_decision", "")),
        action_id=str(attributes.get("operation.id", "")),
        outcome=str(attributes.get("operation.outcome", "")),
        checkpoint_id=str(attributes.get("workflow.checkpoint_id", "")),
    )
    return core.SignalSigner.sign(raw, producer)


def run_demo() -> dict[str, object]:
    producer, store, detector, graph, manager = core.build_system()
    span = capture_effect_span()
    signal = signal_from_span(
        span, producer=producer, trusted_tenant="north",
        event_id="event:otel:42", occurred_at=100,
    )
    receipt = store.admit(signal, received_at=101)
    evidence = store.evidence[receipt.evidence_id]
    alert = detector.detect(evidence)
    assert alert
    incident = manager.promote(alert, graph.scope(alert), model_summary="Untrusted model summary")
    return {
        "sdk": "OpenTelemetry Python SDK",
        "trace_id": signal.trace_id,
        "declared_tenant_ignored": span.attributes["agent.declared_tenant"] != signal.tenant,
        "trusted_tenant": signal.tenant,
        "admission": receipt.status.value,
        "incident_id": incident.incident_id,
        "incident_state": incident.state.value,
        "model_summary_is_authority": False,
        "evidence": asdict(evidence),
    }


if __name__ == "__main__":
    print(run_demo())
