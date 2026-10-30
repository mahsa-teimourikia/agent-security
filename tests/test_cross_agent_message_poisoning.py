"""Security contract tests for Advanced 02 cross-agent message poisoning."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import timedelta
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


COURSE = (
    Path(__file__).parents[1]
    / "curriculum/roadmap/advanced/02-cross-agent-prompt-injection-and-message-poisoning"
)
SPEC = importlib.util.spec_from_file_location("advanced_02_message_lab", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def admit_hostile_message():
    gateway, gate, authorizer, researcher, writer = LAB.build_scenario()
    decision = gateway.admit(researcher, LAB.proposal_for(gateway), now=LAB.NOW)
    assert decision.allowed and decision.message
    return gateway, gate, authorizer, researcher, writer, decision.message


def derive_hostile_artifact():
    gateway, gate, authorizer, researcher, writer, message = admit_hostile_message()
    decision = gate.derive(
        writer,
        message,
        LAB.candidate_for(message),
        now=LAB.NOW,
    )
    assert decision.allowed and decision.artifact
    return gateway, gate, authorizer, researcher, writer, message, decision.artifact


def test_hostile_peer_content_remains_tainted_data() -> None:
    _, _, _, _, _, message = admit_hostile_message()
    assert "ACTION: export_records" in message.content
    assert message.envelope.taint_labels == frozenset(
        {"external-untrusted", "instruction-bearing"}
    )
    assert message.envelope.allowed_uses == frozenset({"internal-brief"})
    assert "export_records" not in message.envelope.allowed_uses


@pytest.mark.parametrize(
    ("sender_change", "proposal_change", "reason"),
    [
        ({"authenticated": False}, {}, "sender-unauthenticated"),
        ({"workload_id": "spiffe://attacker"}, {}, "sender-identity-binding"),
        ({}, {"tenant": "south"}, "tenant"),
        ({}, {"message_type": "grant"}, "message-type"),
        ({}, {"content": "x" * 513}, "message-size"),
    ],
)
def test_admission_rejects_untrusted_control_plane_fields(
    sender_change: dict[str, object],
    proposal_change: dict[str, object],
    reason: str,
) -> None:
    gateway, _, _, researcher, _ = LAB.build_scenario()
    sender = replace(researcher, **sender_change)
    proposal = replace(LAB.proposal_for(gateway), **proposal_change)
    decision = gateway.admit(sender, proposal, now=LAB.NOW)
    assert not decision.allowed
    assert decision.reason == reason
    assert not decision.replayed


def test_recipient_revalidates_integrity_expiry_and_current_sources() -> None:
    gateway, _, _, _, writer, message = admit_hostile_message()

    tampered = replace(message, content=message.content + " tampered")
    assert gateway.consume(writer, tampered, now=LAB.NOW).reason == "content-integrity"

    expired = gateway.consume(
        writer,
        message,
        now=message.envelope.expires_at + timedelta(seconds=1),
    )
    assert expired.reason == "message-expired"

    source = gateway.sources.records["source:vendor-brief"]
    gateway.sources.records = {
        **gateway.sources.records,
        source.source_id: replace(source, version="v4"),
    }
    assert gateway.consume(writer, message, now=LAB.NOW).reason == "source-stale"


def test_message_redelivery_is_idempotent_but_mutation_is_denied() -> None:
    gateway, _, _, researcher, _ = LAB.build_scenario()
    proposal = LAB.proposal_for(gateway)
    first = gateway.admit(researcher, proposal, now=LAB.NOW)
    replay = gateway.admit(researcher, proposal, now=LAB.NOW)
    mutation = gateway.admit(
        researcher,
        replace(proposal, content="changed"),
        now=LAB.NOW,
    )
    assert first.allowed
    assert replay.allowed and replay.replayed
    assert not mutation.allowed and mutation.reason == "message-replay-mismatch"


@pytest.mark.parametrize(
    ("candidate_change", "reason"),
    [
        ({"source_refs": ()}, "provenance-loss"),
        ({"taint_labels": frozenset()}, "taint-loss"),
        ({"allowed_uses": frozenset({"internal-brief", "export"})}, "use-widening"),
    ],
)
def test_transformations_cannot_launder_lineage_or_taint(
    candidate_change: dict[str, object], reason: str
) -> None:
    _, gate, _, _, writer, message = admit_hostile_message()
    candidate = replace(LAB.candidate_for(message), **candidate_change)
    decision = gate.derive(writer, message, candidate, now=LAB.NOW)
    assert not decision.allowed
    assert decision.reason == reason
    assert not gate.artifacts


def test_hostile_message_cannot_grant_a_follow_on_action() -> None:
    _, _, authorizer, _, writer, _, artifact = derive_hostile_artifact()
    decision = authorizer.authorize(
        writer,
        LAB.ActionProposal(
            "operation:export",
            "export_records",
            "case:north:42",
            artifact.artifact_id,
        ),
        now=LAB.NOW,
    )
    assert not decision.allowed
    assert decision.reason == "action-not-allowed"
    assert authorizer.effects == []


def test_atomic_operation_id_allows_one_effect_under_concurrency() -> None:
    _, _, authorizer, _, writer, _, artifact = derive_hostile_artifact()
    proposal = LAB.ActionProposal(
        "operation:brief",
        "draft_internal_brief",
        "case:north:42",
        artifact.artifact_id,
    )
    with ThreadPoolExecutor(max_workers=12) as pool:
        decisions = list(
            pool.map(
                lambda _: authorizer.authorize(writer, proposal, now=LAB.NOW),
                range(24),
            )
        )
    assert all(decision.allowed for decision in decisions)
    assert sum(not decision.replayed for decision in decisions) == 1
    assert sum(decision.reason == "idempotent-action" for decision in decisions) == 23
    assert len(authorizer.effects) == 1
    assert len(authorizer.traces) == 24


@pytest.mark.parametrize("dependency", ["gateway", "registry", "authorizer"])
def test_dependencies_fail_closed_without_effects(dependency: str) -> None:
    gateway, gate, authorizer, researcher, writer = LAB.build_scenario()
    if dependency == "gateway":
        gateway.available = False
        decision = gateway.admit(researcher, LAB.proposal_for(gateway), now=LAB.NOW)
    elif dependency == "registry":
        gateway.sources.available = False
        decision = gateway.admit(researcher, LAB.proposal_for(gateway), now=LAB.NOW)
    else:
        admitted = gateway.admit(researcher, LAB.proposal_for(gateway), now=LAB.NOW)
        assert admitted.message
        transformed = gate.derive(
            writer, admitted.message, LAB.candidate_for(admitted.message), now=LAB.NOW
        )
        assert transformed.artifact
        authorizer.available = False
        decision = authorizer.authorize(
            writer,
            LAB.ActionProposal(
                "operation:x",
                "draft_internal_brief",
                "case:north:42",
                transformed.artifact.artifact_id,
            ),
            now=LAB.NOW,
        )
    assert decision.state is LAB.DecisionState.ERROR
    assert authorizer.effects == []


def test_evaluation_separates_valid_attacks_failures_and_unsafe_baseline() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.total_cases, report.valid_cases, report.attack_cases, report.failure_cases) == (
        20,
        5,
        12,
        3,
    )
    assert report.valid_completion_rate == 1.0
    assert report.attack_forbidden_effect_rate == 0.0
    assert report.failure_error_rate == 1.0
    assert report.poison_propagation_rate == 0.0
    assert report.provenance_loss_acceptance_rate == 0.0
    assert report.unsafe_follow_on_rate == 0.0
    assert report.trace_completeness_rate == 1.0
    assert report.unsafe_baseline_compromise_rate == 1.0
    assert {case.population for case in cases} == {"valid", "attack", "failure"}


def test_redacted_traces_exclude_raw_content_and_signing_material() -> None:
    gateway, gate, authorizer, _, writer, message, artifact = derive_hostile_artifact()
    authorizer.authorize(
        writer,
        LAB.ActionProposal(
            "operation:brief",
            "draft_internal_brief",
            "case:north:42",
            artifact.artifact_id,
        ),
        now=LAB.NOW,
    )
    serialized = str(
        [
            *[asdict(trace) for trace in gateway.traces],
            *[asdict(trace) for trace in gate.traces],
            *[asdict(trace) for trace in authorizer.traces],
        ]
    )
    assert message.content not in serialized
    assert "credential-free-message-course-key" not in serialized
    assert {trace.stage for trace in gateway.traces} == {"admission", "consumption"}


def test_architecture_spec_and_render_are_deterministic() -> None:
    specification = json.loads((COURSE / "architecture-spec.json").read_text())
    assert specification["id"] == "advanced-02-cross-agent-message-boundary"
    assert {node["id"] for node in specification["nodes"]} >= {
        "message",
        "gateway",
        "admitted",
        "transform",
        "authorizer",
        "audit",
    }
    assert len(specification["nodes"]) <= 12
    before = (COURSE / "architecture.svg").read_text()
    subprocess.run(
        [sys.executable, str(COURSE / "render_architecture.py")],
        check=True,
        capture_output=True,
        text=True,
    )
    assert (COURSE / "architecture.svg").read_text() == before
