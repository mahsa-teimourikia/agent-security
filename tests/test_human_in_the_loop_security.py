"""Focused invariants for Intermediate 10 human-in-the-loop security."""

from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "10-human-in-the-loop-security"
SPEC = importlib.util.spec_from_file_location("intermediate_10_hitl_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def scenario():
    return LAB.build_scenario()


def test_submission_ignores_forged_boolean_and_sanitizes_display() -> None:
    plane, requester, approver, _, proposal = scenario()
    hostile = replace(
        proposal,
        client_claimed_approved=True,
        reason='<img src=x onerror="steal()"> damaged shipment',
    )
    submitted = plane.submit(requester, hostile, now=LAB.NOW)
    packet = plane.review_packet(approver, submitted.review_id, now=LAB.NOW)

    assert LAB.unsafe_boolean_gate(hostile)
    assert submitted.status == "pause" and submitted.reason == "review-required"
    assert "<img" not in packet.display_reason
    assert "&lt;img" in packet.display_reason
    assert not plane.operations


def test_reviewer_queue_is_tenant_scoped_and_hides_unknown_ids() -> None:
    plane, requester, approver, _, proposal = scenario()
    submitted = plane.submit(requester, proposal, now=LAB.NOW)
    south = replace(approver, subject="finance:south", tenant="south")

    assert [packet.review_id for packet in plane.queue_for(approver, now=LAB.NOW)] == [submitted.review_id]
    assert plane.queue_for(south, now=LAB.NOW) == ()
    with pytest.raises(PermissionError, match="review-unavailable"):
        plane.review_packet(south, submitted.review_id, now=LAB.NOW)


@pytest.mark.parametrize(
    ("reviewer_change", "reason"),
    [
        ({"authenticated": False}, "reviewer-authentication"),
        ({"roles": frozenset()}, "reviewer-role"),
        ({"tenant": "south"}, "review-unavailable"),
    ],
)
def test_reviewer_identity_and_role_come_from_trusted_context(reviewer_change, reason: str) -> None:
    plane, requester, approver, _, proposal = scenario()
    submitted = plane.submit(requester, proposal, now=LAB.NOW)
    denied = plane.decide(
        replace(approver, **reviewer_change),
        submitted.review_id,
        LAB.ReviewChoice.APPROVE,
        rationale_code="reviewed",
        expected_version=1,
        now=LAB.NOW,
    )
    assert denied.reason == reason
    assert plane.reviews[submitted.review_id].status is LAB.RequestStatus.PENDING


def test_requester_cannot_self_approve_even_with_approver_role() -> None:
    plane, requester, _, _, proposal = scenario()
    submitted = plane.submit(requester, proposal, now=LAB.NOW)
    self_reviewer = replace(requester, roles=frozenset({"finance-approver"}))
    denied = plane.decide(
        self_reviewer,
        submitted.review_id,
        LAB.ReviewChoice.APPROVE,
        rationale_code="self-approved",
        expected_version=1,
        now=LAB.NOW,
    )
    assert denied.reason == "separation-of-duties"


def test_reject_and_request_changes_are_terminal_without_effect() -> None:
    for choice, status in [
        (LAB.ReviewChoice.REJECT, LAB.RequestStatus.REJECTED),
        (LAB.ReviewChoice.REQUEST_CHANGES, LAB.RequestStatus.CHANGES_REQUESTED),
    ]:
        plane, requester, approver, _, proposal = scenario()
        submitted = plane.submit(requester, proposal, now=LAB.NOW)
        result = plane.decide(
            approver,
            submitted.review_id,
            choice,
            rationale_code="reviewed",
            expected_version=1,
            now=LAB.NOW,
        )
        assert result.status == "allow"
        assert plane.reviews[submitted.review_id].status is status
        assert not plane.operations


def test_critical_refund_requires_two_distinct_reviewers() -> None:
    plane, requester, first_reviewer, second_reviewer, proposal = scenario()
    proposal = replace(proposal, amount_cents=5_500)
    submitted = plane.submit(requester, proposal, now=LAB.NOW)
    first = plane.decide(
        first_reviewer,
        submitted.review_id,
        LAB.ReviewChoice.APPROVE,
        rationale_code="risk-reviewed",
        expected_version=1,
        now=LAB.NOW,
    )
    duplicate = plane.decide(
        first_reviewer,
        submitted.review_id,
        LAB.ReviewChoice.APPROVE,
        rationale_code="risk-reviewed",
        expected_version=first.version,
        now=LAB.NOW,
    )
    second = plane.decide(
        second_reviewer,
        submitted.review_id,
        LAB.ReviewChoice.APPROVE,
        rationale_code="risk-reviewed",
        expected_version=first.version,
        now=LAB.NOW,
    )

    assert first.reason == "quorum-pending" and not first.grant_id
    assert duplicate.reason == "reviewer-duplicate"
    assert second.reason == "review-approved" and second.grant_id
    assert plane.reviews[submitted.review_id].grant.approver_subjects == (
        first_reviewer.subject,
        second_reviewer.subject,
    )


def test_optimistic_version_prevents_concurrent_stale_decision() -> None:
    plane, requester, first_reviewer, second_reviewer, proposal = scenario()
    submitted = plane.submit(requester, replace(proposal, amount_cents=5_500), now=LAB.NOW)
    first = plane.decide(
        first_reviewer, submitted.review_id, LAB.ReviewChoice.APPROVE,
        rationale_code="reviewed", expected_version=1, now=LAB.NOW,
    )
    conflict = plane.decide(
        second_reviewer, submitted.review_id, LAB.ReviewChoice.APPROVE,
        rationale_code="reviewed", expected_version=1, now=LAB.NOW,
    )
    assert first.reason == "quorum-pending"
    assert conflict.reason == "review-version-conflict"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"amount_cents": 2_501}, "proposal-changed"),
        ({"resource_id": "case:south:9"}, "proposal-changed"),
        ({"reason": "A different justification"}, "proposal-changed"),
        ({"logical_operation_id": "refund:other"}, "proposal-changed"),
    ],
)
def test_grant_is_bound_to_exact_proposal(change: dict[str, object], reason: str) -> None:
    plane, requester, approver, _, proposal = scenario()
    review_id, grant_id = LAB.approve(plane, requester, approver, proposal)
    result = plane.execute(
        requester,
        review_id,
        grant_id,
        replace(proposal, **change),
        LAB.safe_provider,
        now=LAB.NOW,
    )
    assert result.reason == reason and not result.effect_applied


@pytest.mark.parametrize("stale_kind", ["resource", "policy", "grant"])
def test_resume_reauthorizes_current_state(stale_kind: str) -> None:
    plane, requester, approver, _, proposal = scenario()
    review_id, grant_id = LAB.approve(plane, requester, approver, proposal)
    expected = {
        "resource": "resource-stale",
        "policy": "policy-stale",
        "grant": "grant-expired",
    }[stale_kind]
    if stale_kind == "resource":
        plane.resources[proposal.resource_id].version += 1
    elif stale_kind == "policy":
        plane.policy.version = "northwind-hitl-2"
    now = LAB.NOW + (timedelta(minutes=3) if stale_kind == "grant" else timedelta())
    result = plane.execute(requester, review_id, grant_id, proposal, LAB.safe_provider, now=now)
    assert result.reason == expected and not result.effect_applied


def test_grant_and_logical_operation_are_single_use() -> None:
    plane, requester, approver, _, proposal = scenario()
    review_id, grant_id = LAB.approve(plane, requester, approver, proposal)
    first = plane.execute(requester, review_id, grant_id, proposal, LAB.safe_provider, now=LAB.NOW)
    replay = plane.execute(requester, review_id, grant_id, proposal, LAB.safe_provider, now=LAB.NOW)
    assert first.effect_applied
    assert replay.reason in {"review-not-approved", "grant-replay", "operation-replay"}
    assert len(plane.operations) == 1


def test_atomic_grant_consumption_under_concurrency() -> None:
    assert LAB.concurrency_probe(workers=8) == (1, 7, 1)


def test_timeout_becomes_unknown_and_requires_reconciliation() -> None:
    plane, requester, approver, _, proposal = scenario()
    review_id, grant_id = LAB.approve(plane, requester, approver, proposal)

    def timeout(_proposal):
        raise TimeoutError("synthetic")

    unknown = plane.execute(requester, review_id, grant_id, proposal, timeout, now=LAB.NOW)
    retry = plane.execute(requester, review_id, grant_id, proposal, LAB.safe_provider, now=LAB.NOW)
    reconciled = plane.reconcile(
        requester,
        proposal.logical_operation_id,
        effect_applied=False,
        provider_reference="",
        now=LAB.NOW,
    )
    assert unknown.reason == "provider-outcome-unknown"
    assert retry.reason in {"review-not-approved", "grant-replay", "operation-reconcile-required"}
    assert reconciled.reason == "reconciled-not-applied"
    assert plane.reviews[review_id].status is LAB.RequestStatus.FAILED
    assert plane.operations[proposal.logical_operation_id].status is LAB.OperationStatus.FAILED


def test_review_store_unavailability_is_error_not_approval_or_deny() -> None:
    plane, requester, _, _, proposal = scenario()
    plane.available = False
    result = plane.submit(requester, proposal, now=LAB.NOW)
    assert result.status == "error"
    assert result.reason == "review-store-unavailable"


def test_expired_review_cannot_be_approved() -> None:
    plane, requester, approver, _, proposal = scenario()
    submitted = plane.submit(requester, proposal, now=LAB.NOW)
    denied = plane.decide(
        approver,
        submitted.review_id,
        LAB.ReviewChoice.APPROVE,
        rationale_code="late-review",
        expected_version=1,
        now=LAB.NOW + timedelta(minutes=6),
    )
    assert denied.reason == "review-expired"
    assert plane.reviews[submitted.review_id].status is LAB.RequestStatus.EXPIRED


def test_receipts_are_minimized_and_do_not_copy_sensitive_reason() -> None:
    plane, requester, approver, _, proposal = scenario()
    sensitive = replace(proposal, reason="Customer secret account narrative")
    review_id, grant_id = LAB.approve(plane, requester, approver, sensitive)
    plane.execute(requester, review_id, grant_id, sensitive, LAB.safe_provider, now=LAB.NOW)
    serialized = repr([receipt.__dict__ for receipt in plane.receipts])
    assert "Customer secret" not in serialized
    assert sensitive.resource_id not in serialized
    assert all(receipt.proposal_digest for receipt in plane.receipts)


def test_evaluation_populations_and_metric_denominators() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (20, 5, 12, 3)
    assert report.valid_workflow_completion_rate == 1.0
    assert report.valid_approval_completion_rate == 1.0
    assert report.attack_effect_rate == 0.0
    assert report.approval_bypass_rate == 0.0
    assert report.replay_success_rate == 0.0
    assert report.altered_intent_success_rate == 0.0
    assert report.failure_safe_termination_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert all(case.safe for case in cases)
