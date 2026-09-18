"""OpenTelemetry companion for the Intermediate 03 recovery lab.

The example exports spans to memory so it is credential-free and deterministic.
It records lifecycle decisions and correlation IDs, not prompts, evidence bodies,
checkpoint contents, credentials, or hidden model reasoning.
"""

from __future__ import annotations

from datetime import datetime, timezone
from importlib import import_module
from typing import Callable

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter


core = import_module("03_incident_recovery")


def traced_decision(tracer, name: str, operation: Callable[[], object]):
    with tracer.start_as_current_span(name) as span:
        result = operation()
        span.set_attribute("incident.decision", "allow" if result.allowed else "deny")
        span.set_attribute("incident.reason", result.reason)
        span.set_attribute("incident.phase", result.phase.value)
        span.set_attribute("incident.correlation_id", result.event.correlation_id)
        return result


def demo() -> tuple[core.IncidentRun, tuple[object, ...]]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "incident-recovery-lab"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("agent-security.incident-recovery", "1.0.0")

    now = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
    run, responder, planner, approver, signal, revocation, checkpoint, plan = core.build_scenario(now=now)

    with tracer.start_as_current_span("incident.lifecycle") as root:
        root.set_attribute("incident.run.id", run.run_id)
        root.set_attribute("incident.tenant", run.tenant)
        root.set_attribute("incident.policy.version", run.policy_version)

        assert traced_decision(tracer, "incident.detect", lambda: run.detect(signal, now=now))
        assert traced_decision(
            tracer,
            "incident.contain",
            lambda: run.contain(revocation, responder=responder, now=now),
        )
        assert traced_decision(
            tracer,
            "incident.recovery.propose",
            lambda: run.propose_recovery(plan, checkpoint, planner=planner, now=now),
        )
        approval = core.issue_approval(plan, approver, approval_id="approval-otel", now=now)
        assert traced_decision(
            tracer,
            "incident.recovery.authorize",
            lambda: run.authorize_recovery(
                approval,
                checkpoint,
                now=now,
                current_policy_version=run.policy_version,
                current_credential_version=run.credential_version,
            ),
        )
        with tracer.start_as_current_span("incident.effect") as effect_span:
            effect = run.execute_effect(
                attempt_id="attempt-otel",
                capability="ticket:write",
                now=now,
                provider=lambda _: core.ProviderResult(core.EffectState.CONFIRMED, "provider:T-7"),
            )
            effect_span.set_attribute("incident.operation.id", effect.operation_id)
            effect_span.set_attribute("incident.effect.state", effect.state.value)
            effect_span.set_attribute("incident.reason", effect.reason)

    provider.shutdown()
    spans = exporter.get_finished_spans()
    assert len(spans) == 6
    return run, spans


if __name__ == "__main__":
    _, finished = demo()
    for span in finished:
        print({"name": span.name, "attributes": dict(span.attributes)})
