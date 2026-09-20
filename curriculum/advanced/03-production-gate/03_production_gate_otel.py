"""OpenTelemetry adapter for the production-gate lab.

The adapter records low-cardinality decision metadata. Evidence URIs, risk
rationales, raw blocker text, and attestation material are intentionally absent.
"""
from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Status, StatusCode


CORE_PATH = Path(__file__).with_name("03_production_gate.py")
SPEC = importlib.util.spec_from_file_location("advanced_03_production_gate_core", CORE_PATH)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, core)
SPEC.loader.exec_module(core)


def evaluate_with_trace(
    gate: core.ReleaseGate,
    candidate: core.ReleaseCandidate,
    evidence: list[core.EvidenceEnvelope],
    risks: list[core.RiskEnvelope],
    *,
    now: datetime,
    tracer: object,
) -> core.ReleaseDecision:
    """Evaluate through the trusted gate and export only an allowlisted summary."""

    with tracer.start_as_current_span("release_gate.evaluate") as span:
        decision = gate.evaluate(candidate, evidence, risks, now=now)
        span.set_attribute("release.id", decision.release_id)
        span.set_attribute("release.tenant", decision.tenant)
        span.set_attribute("release.environment", decision.environment)
        span.set_attribute("release.policy_version", decision.policy_version)
        span.set_attribute("release.decision_id", decision.decision_id)
        span.set_attribute("release.state", decision.state.value)
        span.set_attribute("release.blocker_count", len(decision.blockers))
        span.set_attribute("release.evidence_count", len(decision.evidence_ids))
        span.set_attribute("release.risk_acceptance_count", len(decision.risk_acceptance_ids))
        if not decision.ready:
            span.set_status(Status(StatusCode.ERROR, "release gate did not grant readiness"))
        return decision


def credential_free_demo() -> tuple[core.ReleaseDecision, tuple[object, ...]]:
    """Run with an in-memory exporter; no collector, credential, or network."""

    now = datetime(2026, 9, 20, tzinfo=timezone.utc)
    gate, candidate, evidence, risks, _ = core.build_scenario(now=now)
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("agent-security.production-gate")
    decision = evaluate_with_trace(
        gate,
        candidate,
        evidence,
        risks,
        now=now,
        tracer=tracer,
    )
    provider.force_flush()
    return decision, exporter.get_finished_spans()


if __name__ == "__main__":
    release_decision, finished_spans = credential_free_demo()
    print(
        {
            "state": release_decision.state.value,
            "span_count": len(finished_spans),
            "attributes": dict(finished_spans[0].attributes),
        }
    )
