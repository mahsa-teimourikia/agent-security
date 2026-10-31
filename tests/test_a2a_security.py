"""Security and protocol invariants for Advanced 04."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


COURSE = (
    Path(__file__).parents[1]
    / "curriculum/roadmap/advanced/04-agent-to-agent-a2a-security"
)
SPEC = importlib.util.spec_from_file_location("advanced_04_a2a_lab", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def scenario_with_card():
    gateway, principals = LAB.build_scenario()
    card = LAB.admit_default_card(gateway)
    return gateway, principals, card


def scenario_with_task():
    gateway, principals = LAB.build_scenario()
    task = LAB.submit_default_task(gateway, principals)
    return gateway, principals, task


def scenario_with_artifact():
    gateway, principals, task = scenario_with_task()
    admitted = gateway.admit_artifact(
        principals["peer"], task.card_id, LAB.artifact_for(task), step=2
    )
    assert admitted.allowed and admitted.artifact
    return gateway, principals, task, admitted.artifact


def test_unsafe_baseline_treats_protocol_shape_as_authority() -> None:
    baseline = LAB.unsafe_protocol_trust_baseline()
    assert baseline.attack_cases == 4
    assert baseline.accepted_spoof_or_replay == 1
    assert baseline.unauthorized_task_accesses == 1
    assert baseline.callback_ssrf_grants == 1
    assert baseline.forbidden_artifact_effects == 1
    assert baseline.attack_success_rate == 1.0


def test_valid_signature_authenticates_card_but_local_policy_grants_skills() -> None:
    gateway, _ = LAB.build_scenario()
    document = LAB.signed_card(gateway)
    decision = gateway.admit_card(document, now=LAB.NOW, step=0)
    assert decision.allowed and decision.admitted_card
    assert decision.admitted_card.advertised_skills == frozenset(
        {"research.summary", "records.export"}
    )
    assert decision.admitted_card.granted_skills == frozenset({"research.summary"})


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ({"signature": "0" * 64}, "card-signature"),
        ({"expires_at": LAB.NOW}, "card-lifecycle"),
        ({"tenant": "south"}, "card-tenant"),
        ({"protocol_version": "0.3"}, "card-protocol"),
        ({"security_schemes": frozenset({"apiKey"})}, "card-security-scheme"),
    ],
)
def test_card_admission_rejects_untrusted_discovery_claims(
    mutation: dict[str, object], reason: str
) -> None:
    gateway, _ = LAB.build_scenario()
    document = LAB.signed_card(gateway)
    candidate = replace(document, **mutation)
    if "signature" not in mutation:
        registration = gateway.registrations["specialist"]
        candidate = replace(
            candidate,
            signature=gateway.card_signature(
                replace(candidate, signature=""), registration.verification_key
            ),
        )
    decision = gateway.admit_card(candidate, now=LAB.NOW, step=0)
    assert not decision.allowed
    assert decision.reason == reason


def test_same_card_id_with_changed_signed_document_is_not_idempotent() -> None:
    gateway, _ = LAB.build_scenario()
    first = LAB.signed_card(gateway)
    assert gateway.admit_card(first, now=LAB.NOW, step=0).allowed
    registration = gateway.registrations["specialist"]
    changed = replace(first, description="Changed after admission", signature="")
    changed = replace(
        changed,
        signature=gateway.card_signature(changed, registration.verification_key),
    )
    denied = gateway.admit_card(changed, now=LAB.NOW, step=1)
    assert denied.reason == "card-replay-mismatch"


@pytest.mark.parametrize(
    ("principal_change", "proposal_change", "reason"),
    [
        ({"authenticated": False}, {}, "principal-unauthenticated"),
        ({"audience": "records-api"}, {}, "principal-audience"),
        ({"scopes": frozenset()}, {}, "scope"),
        ({}, {"tenant": "south"}, "tenant"),
        ({}, {"skill_id": "records.export"}, "skill-not-authorized"),
        ({}, {"media_type": "application/octet-stream"}, "input-mode"),
        ({}, {"payload_bytes": 4097}, "message-size"),
    ],
)
def test_task_submission_uses_transport_identity_and_local_policy(
    principal_change: dict[str, object],
    proposal_change: dict[str, object],
    reason: str,
) -> None:
    gateway, principals, card = scenario_with_card()
    principal = replace(principals["owner"], **principal_change)
    proposal = replace(LAB.task_message(), **proposal_change)
    denied = gateway.submit_task(
        principal, card.card_id, proposal, now=LAB.NOW, step=1
    )
    assert not denied.allowed
    assert denied.reason == reason
    assert not gateway.tasks


def test_message_id_is_exactly_idempotent_and_mutation_is_denied() -> None:
    gateway, principals, card = scenario_with_card()
    proposal = LAB.task_message()
    first = gateway.submit_task(
        principals["owner"], card.card_id, proposal, now=LAB.NOW, step=1
    )
    replay = gateway.submit_task(
        principals["owner"], card.card_id, proposal, now=LAB.NOW, step=2
    )
    mutation = gateway.submit_task(
        principals["owner"],
        card.card_id,
        replace(proposal, payload_digest="0" * 64),
        now=LAB.NOW,
        step=3,
    )
    assert first.allowed and replay.allowed and replay.replayed
    assert first.task_id == replay.task_id and len(gateway.tasks) == 1
    assert mutation.reason == "message-replay-mismatch"


def test_every_task_operation_rechecks_owner_and_scope() -> None:
    gateway, principals, task = scenario_with_task()
    other = principals["other"]
    read = gateway.get_task(other, task.task_id, history_length=1, step=2)
    write = gateway.add_message(
        other,
        task.task_id,
        LAB.task_message(message_id="message:other", context_id=task.context_id),
        step=3,
    )
    cancel = gateway.cancel_task(other, task.task_id, step=4)
    assert {read.reason, write.reason, cancel.reason} == {"task-access"}
    assert task.state is LAB.TaskState.SUBMITTED


def test_context_binding_and_history_limit_are_server_enforced() -> None:
    gateway, principals, task = scenario_with_task()
    wrong_context = gateway.add_message(
        principals["owner"],
        task.task_id,
        LAB.task_message(message_id="message:followup", context_id="context:other"),
        step=2,
    )
    too_much_history = gateway.get_task(
        principals["owner"], task.task_id, history_length=6, step=3
    )
    assert wrong_context.reason == "context-binding"
    assert too_much_history.reason == "history-limit"
    assert len(task.history_digests) == 1


def test_artifact_integrity_is_checked_and_content_remains_tainted() -> None:
    gateway, principals, task = scenario_with_task()
    proposal = LAB.artifact_for(task)
    admitted = gateway.admit_artifact(
        principals["peer"], task.card_id, proposal, step=2
    )
    corrupted = gateway.admit_artifact(
        principals["peer"],
        task.card_id,
        replace(proposal, artifact_id="artifact:corrupt", content_digest="0" * 64),
        step=3,
    )
    assert admitted.allowed and admitted.artifact
    assert admitted.artifact.taint == frozenset(
        {"external-peer", "untrusted-content"}
    )
    assert corrupted.reason == "artifact-integrity"


def test_artifact_text_cannot_grant_a_follow_on_effect() -> None:
    gateway, principals, task, artifact = scenario_with_artifact()
    denied = gateway.authorize_effect(
        principals["owner"],
        LAB.EffectProposal(
            "operation:export",
            task.task_id,
            artifact.artifact_id,
            "export-customer-records",
            "case:north:42",
        ),
        step=3,
    )
    assert denied.reason == "effect-not-authorized"
    assert not task.effects


def test_effect_idempotency_is_atomic_under_concurrency() -> None:
    gateway, principals, task, artifact = scenario_with_artifact()
    proposal = LAB.EffectProposal(
        "operation:brief:atomic",
        task.task_id,
        artifact.artifact_id,
        "store-internal-research-brief",
        "case:north:42",
    )

    def execute(_: int):
        return gateway.authorize_effect(principals["owner"], proposal, step=3)

    with ThreadPoolExecutor(max_workers=12) as pool:
        decisions = list(pool.map(execute, range(24)))
    assert all(decision.allowed for decision in decisions)
    assert sum(not decision.replayed for decision in decisions) == 1
    assert len(task.effects) == 1
    assert len({decision.effect_id for decision in decisions}) == 1


@pytest.mark.parametrize(
    ("url", "records", "reason"),
    [
        ("http://events.north.example/a2a", ("93.184.216.34",), "callback-destination"),
        ("https://attacker.example/a2a", ("93.184.216.34",), "callback-destination"),
        ("https://events.north.example/a2a", ("127.0.0.1",), "callback-private-address"),
        ("https://events.north.example/a2a", ("169.254.169.254",), "callback-private-address"),
    ],
)
def test_callback_registration_blocks_ssrf(
    url: str, records: tuple[str, ...], reason: str
) -> None:
    gateway, principals, task = scenario_with_task()
    gateway.resolver.records["events.north.example"] = records
    denied = gateway.register_callback(
        principals["owner"],
        task.task_id,
        LAB.CallbackProposal(
            "callback:ssrf", task.task_id, task.tenant, url, "token", LAB.NOW + 60
        ),
        now=LAB.NOW,
        step=2,
    )
    assert denied.reason == reason
    assert not task.callbacks


def test_callback_delivery_binds_dns_and_disables_redirects() -> None:
    gateway, principals, task = scenario_with_task()
    proposal = LAB.CallbackProposal(
        "callback:bound",
        task.task_id,
        task.tenant,
        "https://events.north.example/a2a/events",
        "synthetic-token",
        LAB.NOW + 60,
    )
    registered = gateway.register_callback(
        principals["owner"], task.task_id, proposal, now=LAB.NOW, step=2
    )
    assert registered.allowed and registered.callback
    assert registered.callback.redirects_allowed is False
    gateway.resolver.records["events.north.example"] = ("8.8.8.8",)
    denied = gateway.authorize_callback_delivery(
        task.task_id, proposal.callback_id, now=LAB.NOW, step=3
    )
    assert denied.reason == "callback-dns-rebind"


@pytest.mark.parametrize(
    ("dependency", "operation", "reason"),
    [
        ("registry_available", "card", "registry-unavailable"),
        ("task_store_available", "task", "task-store-unavailable"),
        ("resolver_available", "callback", "resolver-unavailable"),
        ("effect_executor_available", "effect", "effect-executor-unavailable"),
    ],
)
def test_dependency_failures_are_errors_not_fake_denials(
    dependency: str, operation: str, reason: str
) -> None:
    gateway, principals = LAB.build_scenario()
    if operation == "card":
        setattr(gateway, dependency, False)
        decision = gateway.admit_card(LAB.signed_card(gateway), now=LAB.NOW, step=0)
    else:
        task = LAB.submit_default_task(gateway, principals)
        if operation == "callback":
            setattr(gateway, dependency, False)
            decision = gateway.register_callback(
                principals["owner"],
                task.task_id,
                LAB.CallbackProposal(
                    "callback:error",
                    task.task_id,
                    task.tenant,
                    "https://events.north.example/a2a",
                    "token",
                    LAB.NOW + 60,
                ),
                now=LAB.NOW,
                step=2,
            )
        elif operation == "effect":
            admitted = gateway.admit_artifact(
                principals["peer"], task.card_id, LAB.artifact_for(task), step=2
            )
            setattr(gateway, dependency, False)
            decision = gateway.authorize_effect(
                principals["owner"],
                LAB.EffectProposal(
                    "operation:error",
                    task.task_id,
                    admitted.artifact.artifact_id,
                    "store-internal-research-brief",
                    "case:north:42",
                ),
                step=3,
            )
        else:
            setattr(gateway, dependency, False)
            card = LAB.admit_default_card(gateway)
            decision = gateway.submit_task(
                principals["owner"], card.card_id, LAB.task_message(), now=LAB.NOW, step=1
            )
    assert decision.state is LAB.DecisionState.ERROR
    assert decision.reason == reason


def test_receipts_are_content_free_and_secret_free() -> None:
    gateway, principals, task = scenario_with_task()
    proposal = LAB.artifact_for(task)
    gateway.admit_artifact(principals["peer"], task.card_id, proposal, step=2)
    serialized = json.dumps([asdict(receipt) for receipt in gateway.receipts])
    assert proposal.content not in serialized
    assert "synthetic-course-card-key-v1" not in serialized
    assert "instruction" not in serialized


def test_evaluation_reports_exact_populations_and_metrics() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.total_cases, report.valid_cases, report.attack_cases, report.failure_cases) == (
        20,
        5,
        12,
        3,
    )
    assert report.valid_completion_rate == 1.0
    assert report.spoof_replay_acceptance_rate == 0.0
    assert report.unauthorized_task_access_rate == 0.0
    assert report.callback_ssrf_acceptance_rate == 0.0
    assert report.artifact_forbidden_effect_rate == 0.0
    assert report.failure_error_rate == 1.0
    assert report.audit_coverage_rate == 1.0
    assert report.unsafe_baseline_attack_success_rate == 1.0
    assert all(case.safe and case.receipt_complete for case in cases)


def test_architecture_spec_is_bounded_and_rendering_is_deterministic() -> None:
    specification = json.loads((COURSE / "architecture-spec.json").read_text())
    assert specification["id"] == "advanced-04-a2a-trust-boundary"
    assert len(specification["nodes"]) <= 12
    before = (COURSE / "architecture.svg").read_text()
    subprocess.run(
        [sys.executable, str(COURSE / "render_architecture.py")],
        check=True,
        capture_output=True,
        text=True,
    )
    assert (COURSE / "architecture.svg").read_text() == before
