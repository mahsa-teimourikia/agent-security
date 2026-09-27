"""Focused tests for Intermediate 02 checkpoint and durable execution security."""
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "02-state-checkpoint-and-durable-execution-security"
SPEC = importlib.util.spec_from_file_location("intermediate_02_durable_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def test_declared_evaluation_separates_valid_attacks_and_failures() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (16, 4, 10, 2)
    assert report.valid_resume_success_rate == report.trace_completeness_rate == 1.0
    assert report.unsafe_resume_rate == 0.0
    assert report.duplicate_effect_count == 0
    assert report.integrity_detection_rate == report.concurrency_conflict_rate == 1.0
    assert report.baseline_attack_acceptance_rate == 1.0
    assert all(item.terminal_status == "error" for item in cases if item.kind is LAB.CaseKind.FAILURE)


def test_server_owned_checkpoint_tampering_is_detected_before_resume() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    service.store.records[checkpoint.checkpoint_id] = replace(
        checkpoint, tenant="south", state={"case_id": "case-999"}
    )
    decision = service.resume(
        LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:tamper", now=LAB.NOW
    )
    assert (decision.status, decision.reason, decision.lease) == (
        LAB.ResumeStatus.DENY, "checkpoint-integrity", None
    )


def test_entire_checkpoint_parent_chain_is_verified() -> None:
    service, root, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    first = service.resume(LAB.actor(), root.checkpoint_id, resume_request_id="resume:root", now=LAB.NOW)
    child = service.commit(
        LAB.actor(), first.lease, status=LAB.RunStatus.PAUSED,
        state=first.lease.state, pending_step=root.pending_step,
        pending_effect=root.pending_effect, approval_id=root.approval_id,
        now=LAB.NOW + timedelta(seconds=1),
    )
    second = service.resume(
        LAB.actor("request:child"), child.checkpoint_id,
        resume_request_id="resume:child", now=LAB.NOW + timedelta(seconds=2),
    )
    grandchild = service.commit(
        LAB.actor("request:child"), second.lease, status=LAB.RunStatus.PAUSED,
        state=second.lease.state, pending_step=child.pending_step,
        pending_effect=child.pending_effect, approval_id=child.approval_id,
        now=LAB.NOW + timedelta(seconds=3),
    )
    service.store.records[root.checkpoint_id] = replace(root, state={"case_id": "tampered"})
    decision = service.resume(
        LAB.actor("request:grandchild"), grandchild.checkpoint_id,
        resume_request_id="resume:grandchild", now=LAB.NOW + timedelta(seconds=4),
    )
    assert (decision.status, decision.reason) == (LAB.ResumeStatus.DENY, "checkpoint-integrity")


def test_resume_request_is_idempotent_but_concurrent_claim_conflicts() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    first = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:same", now=LAB.NOW)
    retry = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:same", now=LAB.NOW)
    concurrent = service.resume(
        LAB.actor("request:other"), checkpoint.checkpoint_id,
        resume_request_id="resume:other", now=LAB.NOW,
    )
    assert first.status is LAB.ResumeStatus.READY
    assert retry.status is LAB.ResumeStatus.IDEMPOTENT
    assert retry.lease.lease_id == first.lease.lease_id
    assert (concurrent.status, concurrent.reason) == (LAB.ResumeStatus.CONFLICT, "resume-already-claimed")


def test_current_policy_and_tool_contract_are_rechecked_at_effect_boundary() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    resumed = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:effect", now=LAB.NOW)
    service.policy.current = replace(service.policy.current, tool_version="case-tool-v4")
    effect = service.execute_pending(LAB.actor(), resumed.lease, now=LAB.NOW)
    assert (effect.status, effect.reason) == (LAB.EffectStatus.DENY, "tool-version-changed")
    assert service.provider.dispatch_count == 0


def test_provider_preflight_failure_does_not_consume_approval() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    resumed = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:provider", now=LAB.NOW)
    service.provider.available = False
    effect = service.execute_pending(LAB.actor(), resumed.lease, now=LAB.NOW)
    assert (effect.status, effect.reason) == (LAB.EffectStatus.ERROR, "provider-unavailable")
    assert service.approvals.receipts[checkpoint.approval_id].state is LAB.ApprovalState.AVAILABLE
    assert service.provider.dispatch_count == 0


def test_unknown_provider_outcome_is_reconciled_without_redispatch() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    resumed = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:unknown", now=LAB.NOW)
    unknown = service.execute_pending(
        LAB.actor(), resumed.lease, now=LAB.NOW, timeout_after_provider_commit=True
    )
    assert unknown.status is LAB.EffectStatus.UNKNOWN
    resumed_again = service.resume(
        LAB.actor("request:reconcile"), unknown.checkpoint.checkpoint_id,
        resume_request_id="resume:reconcile", now=LAB.NOW + timedelta(seconds=1),
    )
    reconciled = service.reconcile_unknown(
        LAB.actor("request:reconcile"), resumed_again.lease,
        now=LAB.NOW + timedelta(seconds=1),
    )
    assert reconciled.status is LAB.EffectStatus.RECONCILED
    assert reconciled.checkpoint.status is LAB.RunStatus.COMPLETED
    assert service.provider.dispatch_count == 1


def test_operation_id_collision_is_denied_not_marked_complete() -> None:
    service, checkpoint, effect = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    service.provider.committed[effect.operation_id] = LAB.ProviderReceipt(
        effect.operation_id, LAB.digest([effect.effect_digest, "other"]),
        "provider:other", LAB.NOW,
    )
    resumed = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:collision", now=LAB.NOW)
    decision = service.execute_pending(LAB.actor(), resumed.lease, now=LAB.NOW)
    assert (decision.status, decision.reason) == (LAB.EffectStatus.DENY, "operation-id-collision")
    assert service.store.current(checkpoint.run_id).status is LAB.RunStatus.PAUSED


def test_only_registered_deterministic_migration_can_resume() -> None:
    service, checkpoint, _ = LAB.build_system()
    decision = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:migrate", now=LAB.NOW)
    assert decision.status is LAB.ResumeStatus.READY
    assert decision.lease.target_schema_version == 2
    assert decision.lease.state["review_queue"] == "standard"

    service, checkpoint, _ = LAB.build_system(workflow_version="legacy", schema_version=0)
    denied = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:no-migrate", now=LAB.NOW)
    assert (denied.status, denied.reason) == (LAB.ResumeStatus.PAUSED, "migration-unavailable")


def test_nondeterministic_migration_is_an_error_not_a_resume() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="legacy", schema_version=0)
    counter = {"value": 0}

    def unstable(state):
        counter["value"] += 1
        return {**state, "counter": counter["value"]}

    service.migrations.register("legacy", "workflow-v2", 0, 2, unstable)
    decision = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:unstable", now=LAB.NOW)
    assert (decision.status, decision.reason) == (LAB.ResumeStatus.ERROR, "migration-nondeterministic")


def test_expired_or_wrong_effect_approval_pauses_resume() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    approval = service.approvals.receipts[checkpoint.approval_id]
    service.approvals.receipts[approval.approval_id] = replace(
        approval, expires_at=LAB.NOW
    )
    expired = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:expired-approval", now=LAB.NOW)
    assert (expired.status, expired.reason) == (LAB.ResumeStatus.PAUSED, "approval-expired")


def test_step_budget_exhaustion_pauses_without_lease() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    exhausted = service.signer.seal(replace(checkpoint, remaining_steps=0))
    service.store.records[checkpoint.checkpoint_id] = exhausted
    decision = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:budget", now=LAB.NOW)
    assert (decision.status, decision.reason, decision.lease) == (
        LAB.ResumeStatus.PAUSED, "step-budget-exhausted", None
    )


def test_receipts_are_bounded_and_do_not_copy_checkpoint_state() -> None:
    service, checkpoint, _ = LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    decision = service.resume(LAB.actor(), checkpoint.checkpoint_id, resume_request_id="resume:trace", now=LAB.NOW)
    rendered = repr(decision.receipt)
    assert "draft_resolution" not in rendered
    assert "resolved" not in rendered
    assert "analyst-7" not in rendered
    assert decision.receipt.lease_id

