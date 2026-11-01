"""Security and pedagogy tests for Enterprise 01."""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys
from threading import Thread

import pytest


COURSE = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/01-secure-long-running-agents"
sys.path.insert(0, str(COURSE))
import secure_long_running_agents as lab


def resumed_system():
    plane, actor, effect = lab.build_system()
    result = plane.resume(
        actor, "run:north:42", resume_request_id="resume:1", expected_version=1, now=lab.NOW
    )
    assert result.lease is not None
    return plane, actor, effect, result.lease


def test_valid_resume_issues_current_version_bound_lease() -> None:
    plane, actor, _, lease = resumed_system()
    checkpoint = plane.runs["run:north:42"].checkpoint
    assert lease.policy_version == plane.authority.policy_version
    assert lease.credential_version == "credential-v3"
    assert lease.budget_epoch == "budget-2026-q4"
    assert lease.policy_version != checkpoint.policy_version
    assert checkpoint.phase is lab.RunPhase.RUNNING


def test_valid_checkpoint_does_not_prove_current_authority() -> None:
    plane, actor, _ = lab.build_system()
    assert plane.signer.verify(plane.runs["run:north:42"].checkpoint)
    plane.authority.allowed_subjects.clear()
    result = plane.resume(actor, "run:north:42", resume_request_id="revoked", expected_version=1, now=lab.NOW)
    assert result.decision is lab.Decision.DENY
    assert result.reason == "subject-revoked"


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda plane, actor: replace(actor, authenticated=False), "unauthenticated"),
        (lambda plane, actor: replace(actor, tenant="south"), "tenant-mismatch"),
        (lambda plane, actor: replace(actor, credential_version="credential-v2"), "credential-stale"),
        (lambda plane, actor: replace(actor, scopes=frozenset()), "scope-missing"),
        (lambda plane, actor: (plane.authority.allowed_subjects.clear() or actor), "subject-revoked"),
        (
            lambda plane, actor: (
                plane.authority.intent_digests.__setitem__("run:north:42", "new-intent") or actor
            ),
            "intent-changed",
        ),
        (
            lambda plane, actor: (
                plane.authority.remaining_effects.__setitem__("run:north:42", 0) or actor
            ),
            "budget-exhausted",
        ),
    ],
)
def test_resume_revalidates_each_current_boundary(mutate, reason: str) -> None:
    plane, actor, _ = lab.build_system()
    result = plane.resume(
        mutate(plane, actor), "run:north:42", resume_request_id=reason,
        expected_version=1, now=lab.NOW,
    )
    assert result.decision is lab.Decision.DENY
    assert result.reason == reason


def test_authority_outage_is_unknown_not_allow() -> None:
    plane, actor, _ = lab.build_system()
    plane.authority.available = False
    result = plane.resume(actor, "run:north:42", resume_request_id="outage", expected_version=1, now=lab.NOW)
    assert result.decision is lab.Decision.UNKNOWN
    assert result.reason == "authority-unavailable"


def test_checkpoint_state_tamper_is_rejected() -> None:
    plane, actor, _ = lab.build_system()
    record = plane.runs["run:north:42"]
    record.checkpoint.state["step"] = "skip-approval"
    result = plane.resume(actor, "run:north:42", resume_request_id="tampered", expected_version=1, now=lab.NOW)
    assert result.reason == "checkpoint-integrity"


def test_signature_tamper_is_rejected() -> None:
    plane, actor, _ = lab.build_system()
    record = plane.runs["run:north:42"]
    record.checkpoint = replace(record.checkpoint, signature="forged")
    result = plane.resume(actor, "run:north:42", resume_request_id="forged", expected_version=1, now=lab.NOW)
    assert result.reason == "checkpoint-integrity"


def test_unsupported_workflow_version_is_rejected() -> None:
    plane, actor, _ = lab.build_system()
    record = plane.runs["run:north:42"]
    record.checkpoint = plane.signer.seal(
        replace(record.checkpoint, workflow_version="workflow-v0", signature="")
    )
    result = plane.resume(actor, "run:north:42", resume_request_id="old", expected_version=1, now=lab.NOW)
    assert result.reason == "workflow-version-unsupported"


def test_resume_request_is_idempotent() -> None:
    plane, actor, _ = lab.build_system()
    first = plane.resume(actor, "run:north:42", resume_request_id="same", expected_version=1, now=lab.NOW)
    replay = plane.resume(actor, "run:north:42", resume_request_id="same", expected_version=1, now=lab.NOW)
    assert replay.decision is lab.Decision.IDEMPOTENT
    assert replay.lease == first.lease


def test_second_resume_owner_conflicts() -> None:
    plane, actor, _ = lab.build_system()
    plane.resume(actor, "run:north:42", resume_request_id="owner-a", expected_version=1, now=lab.NOW)
    second = plane.resume(actor, "run:north:42", resume_request_id="owner-b", expected_version=2, now=lab.NOW)
    assert second.decision is lab.Decision.CONFLICT
    assert second.reason == "resume-owner-active"


def test_stale_optimistic_version_conflicts() -> None:
    plane, actor, _ = lab.build_system()
    result = plane.resume(actor, "run:north:42", resume_request_id="stale-version", expected_version=0, now=lab.NOW)
    assert result.decision is lab.Decision.CONFLICT
    assert result.reason == "version-conflict"


def test_concurrent_resume_produces_one_owner() -> None:
    decisions = lab.concurrent_resume_demo()
    assert decisions.count(lab.Decision.ALLOW) == 1
    assert len(decisions) == 2


def test_heartbeat_extends_liveness_not_authority_expiry() -> None:
    plane, actor, _, lease = resumed_system()
    result = plane.heartbeat(actor, "run:north:42", lease.lease_id, now=lab.NOW + timedelta(minutes=1))
    assert result.decision is lab.Decision.ALLOW
    assert result.lease.heartbeat_deadline == lab.NOW + timedelta(minutes=3)
    assert result.lease.expires_at == lease.expires_at


def test_heartbeat_rejects_wrong_owner() -> None:
    plane, actor, _, lease = resumed_system()
    wrong = replace(actor, subject="analyst:north:8")
    result = plane.heartbeat(wrong, "run:north:42", lease.lease_id, now=lab.NOW)
    assert result.reason == "lease-owner-mismatch"


def test_orphan_sweep_revokes_expired_heartbeat_owner() -> None:
    plane, _, _, lease = resumed_system()
    assert plane.sweep_orphans(now=lease.heartbeat_deadline) == ("run:north:42",)
    record = plane.runs["run:north:42"]
    assert record.active_lease is None
    assert record.checkpoint.phase is lab.RunPhase.WAITING


def test_orphan_sweep_keeps_live_owner() -> None:
    plane, _, _, lease = resumed_system()
    assert plane.sweep_orphans(now=lease.heartbeat_deadline - timedelta(microseconds=1)) == ()


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda plane: setattr(plane.authority, "policy_version", "policy-new"), "policy-changed"),
        (
            lambda plane: plane.authority.credential_versions.__setitem__(
                "analyst:north:7", "credential-v4"
            ),
            "credential-revoked",
        ),
        (lambda plane: setattr(plane.authority, "budget_epoch", "budget-2027-q1"), "budget-epoch-changed"),
        (
            lambda plane: plane.authority.intent_digests.__setitem__("run:north:42", "changed"),
            "intent-changed",
        ),
    ],
)
def test_stale_lease_cannot_execute_after_authority_change(mutate, reason: str) -> None:
    plane, actor, effect, lease = resumed_system()
    mutate(plane)
    result = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:stale", provider=lab.SyntheticProvider(), now=lab.NOW,
    )
    assert result.decision is lab.Decision.DENY
    assert result.reason == reason


def test_effect_at_heartbeat_deadline_is_denied() -> None:
    plane, actor, effect, lease = resumed_system()
    result = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:deadline", provider=lab.SyntheticProvider(), now=lease.heartbeat_deadline,
    )
    assert result.reason == "heartbeat-expired"


def test_effect_at_lease_expiry_is_denied() -> None:
    plane, actor, effect, lease = resumed_system()
    result = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:expiry", provider=lab.SyntheticProvider(), now=lease.expires_at,
    )
    assert result.reason == "lease-expired"


def test_changed_effect_is_denied() -> None:
    plane, actor, effect, lease = resumed_system()
    changed = replace(effect, arguments=(("resolution", "fraud"),))
    result = plane.execute(
        actor, "run:north:42", lease.lease_id, changed,
        attempt_id="attempt:changed", provider=lab.SyntheticProvider(), now=lab.NOW,
    )
    assert result.reason == "effect-changed"


def test_changed_logical_operation_id_is_denied() -> None:
    plane, actor, effect, lease = resumed_system()
    changed = replace(effect, logical_operation_id="close-case:other")
    result = plane.execute(
        actor, "run:north:42", lease.lease_id, changed,
        attempt_id="attempt:op-change", provider=lab.SyntheticProvider(), now=lab.NOW,
    )
    assert result.reason == "operation-id-changed"


def test_expired_approval_is_denied() -> None:
    plane, actor, effect = lab.build_system()
    approval_id = plane.runs["run:north:42"].checkpoint.approval_id
    plane.approvals[approval_id] = replace(plane.approvals[approval_id], expires_at=lab.NOW)
    result = plane.resume(
        actor, "run:north:42", resume_request_id="expired-approval",
        expected_version=1, now=lab.NOW,
    )
    assert result.reason == "approval-expired"
    assert result.lease is None


def test_successful_effect_consumes_approval_and_budget() -> None:
    plane, actor, effect, lease = resumed_system()
    provider = lab.SyntheticProvider()
    result = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:success", provider=provider, now=lab.NOW,
    )
    approval = plane.approvals[plane.runs["run:north:42"].checkpoint.approval_id]
    assert result.decision is lab.Decision.ALLOW
    assert approval.used
    assert plane.authority.remaining_effects["run:north:42"] == 0
    assert provider.dispatches == 1


def test_timeout_after_commit_never_blindly_retries() -> None:
    plane, actor, effect, lease = resumed_system()
    provider = lab.SyntheticProvider()
    first = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:1", provider=provider, now=lab.NOW, timeout_after_commit=True,
    )
    retry = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:2", provider=provider, now=lab.NOW,
    )
    assert first.decision is lab.Decision.UNKNOWN
    assert retry.reason == "reconcile-before-retry"
    assert provider.dispatches == 1


def test_reconcile_confirms_committed_effect() -> None:
    plane, actor, effect, lease = resumed_system()
    provider = lab.SyntheticProvider()
    plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:1", provider=provider, now=lab.NOW, timeout_after_commit=True,
    )
    result = plane.reconcile(actor, "run:north:42", effect.logical_operation_id, provider, now=lab.NOW)
    assert result.reason == "committed-effect-reconciled"
    assert plane.runs["run:north:42"].checkpoint.phase is lab.RunPhase.COMPLETED
    assert provider.dispatches == 1


def test_reconcile_outage_preserves_unknown() -> None:
    plane, actor, effect, lease = resumed_system()
    provider = lab.SyntheticProvider()
    plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:1", provider=provider, now=lab.NOW, timeout_after_commit=True,
    )
    provider.available = False
    result = plane.reconcile(actor, "run:north:42", effect.logical_operation_id, provider, now=lab.NOW)
    assert result.decision is lab.Decision.UNKNOWN
    assert plane.runs["run:north:42"].operations[effect.logical_operation_id].state is lab.OperationState.UNKNOWN


def test_operation_id_collision_is_rejected() -> None:
    plane, actor, effect, lease = resumed_system()
    record = plane.runs["run:north:42"]
    record.operations[effect.logical_operation_id] = lab.OperationRecord(
        effect.logical_operation_id, "different-digest", "attempt:old", lab.OperationState.COMMITTED
    )
    result = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:new", provider=lab.SyntheticProvider(), now=lab.NOW,
    )
    assert result.reason == "operation-id-collision"


def test_receipts_minimize_subject_identity() -> None:
    plane, actor, _, _ = resumed_system()
    receipt = plane.receipts[-1]
    assert actor.subject not in receipt.subject_digest
    assert len(receipt.subject_digest) == 16
    assert receipt.policy_version == plane.authority.policy_version


def test_evaluation_declares_populations_and_exact_denominators() -> None:
    report = lab.evaluate_controls()
    assert (report.valid_cases, report.attack_cases, report.boundary_cases, report.failure_cases) == (1, 4, 1, 2)
    assert report.cases == 8
    assert report.valid_completion_rate == 1
    assert report.unsafe_resume_rate == 0
    assert report.stale_lease_use_rate == 0
    assert report.duplicate_effect_rate == 0
    assert report.orphan_detection_rate == 1
    assert report.safe_failure_rate == 1


def test_lab_entrypoint_runs() -> None:
    result = __import__("subprocess").run(
        [sys.executable, str(COURSE / "lab.py")],
        cwd=COURSE.parents[3],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert '"unsafe_resume_rate": 0.0' in result.stdout


def test_sdk_adapter_source_places_gate_before_restore() -> None:
    source = (COURSE / "sdk_adapter.py").read_text()
    gate = source.index("if resume.decision not in")
    restore = source.index("RunState.from_json", gate)
    assert gate < restore
    assert "api key" in source.lower()
