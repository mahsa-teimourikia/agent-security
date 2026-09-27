"""Focused regressions for Foundation 05 authorization and approval."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "05-authorization-approval-and-least-privilege"
SPEC = importlib.util.spec_from_file_location("foundation_05_lab_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


def test_evaluation_populations_and_metrics_are_explicit() -> None:
    report, cases = LAB.evaluate_controls(now=NOW)
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (14, 4, 8, 2)
    assert report.attack_block_rate == 1.0
    assert report.attack_effect_rate == 0.0
    assert report.valid_task_success_rate == 1.0
    assert report.blocked_valid_task_rate == 0.0
    assert report.baseline_attack_acceptance_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert all(case.trace_complete for case in cases)


def test_model_claims_and_tool_visibility_never_create_authority() -> None:
    pep, actor, _, cases = LAB.build_scenario()
    unprivileged = replace(actor, roles=frozenset(), scopes=frozenset())
    proposal = LAB.refund_proposal("claim:1", 500, model_claimed_role="admin")
    decision = pep.enforce(unprivileged, proposal, now=NOW)
    assert decision.status is LAB.DecisionStatus.DENY
    assert decision.reason == "scope"
    assert LAB.minimum_tool_set(unprivileged, cases["case:north:42"]) == frozenset()
    assert "admin_refunds" not in LAB.minimum_tool_set(actor, cases["case:north:42"])


def test_high_risk_effect_requires_independent_exact_approval() -> None:
    pep, actor, approver, _ = LAB.build_scenario()
    proposal = LAB.refund_proposal("exact:1", 2_500)
    decision = pep.pdp.evaluate(actor, proposal)
    assert decision.status is LAB.DecisionStatus.PAUSE
    receipt = LAB.authorize_and_approve(
        pep, actor, approver, proposal, approval_id="approval:exact", now=NOW
    )
    altered = replace(proposal, amount_cents=2_501)
    denied = pep.enforce(actor, altered, approval_id=receipt.approval_id, now=NOW)
    allowed = pep.enforce(actor, proposal, approval_id=receipt.approval_id, now=NOW)
    replay = pep.enforce(actor, proposal, approval_id=receipt.approval_id, now=NOW)
    assert (denied.reason, allowed.reason, replay.reason) == (
        "approval-binding",
        "approved-effect",
        "operation-replayed",
    )
    assert len(pep.effects) == 1


@pytest.mark.parametrize(
    ("approver_change", "reason"),
    [
        ({"subject": "employee:7"}, "separation-of-duties"),
        ({"tenant": "south"}, "approver-tenant"),
        ({"roles": frozenset({"support-agent"})}, "approver-role"),
        ({"authenticated": False}, "approver-unauthenticated"),
    ],
)
def test_approval_issuance_enforces_independence(approver_change: dict[str, object], reason: str) -> None:
    pep, actor, approver, _ = LAB.build_scenario()
    proposal = LAB.refund_proposal("issuance:1", 2_500)
    with pytest.raises(ValueError, match=reason):
        LAB.authorize_and_approve(
            pep,
            actor,
            replace(approver, **approver_change),
            proposal,
            approval_id=f"approval:{reason}",
            now=NOW,
        )


def test_expiry_revocation_policy_and_resource_changes_fail_closed() -> None:
    pep, actor, approver, cases = LAB.build_scenario()
    expired_proposal = LAB.refund_proposal("stale:expiry", 2_500)
    expired = LAB.authorize_and_approve(
        pep, actor, approver, expired_proposal, approval_id="approval:expired", now=NOW
    )
    assert pep.enforce(
        actor,
        expired_proposal,
        approval_id=expired.approval_id,
        now=NOW + timedelta(minutes=6),
    ).reason == "approval-expired"

    revoked_proposal = LAB.refund_proposal("stale:revoked", 2_500)
    revoked = LAB.authorize_and_approve(
        pep, actor, approver, revoked_proposal, approval_id="approval:revoked", now=NOW
    )
    pep.approvals.revoke(revoked.approval_id)
    assert pep.enforce(actor, revoked_proposal, approval_id=revoked.approval_id, now=NOW).reason == "approval-revoked"

    resource_proposal = LAB.refund_proposal("stale:resource", 2_500)
    resource_receipt = LAB.authorize_and_approve(
        pep, actor, approver, resource_proposal, approval_id="approval:resource", now=NOW
    )
    cases[resource_proposal.resource_id].version += 1
    assert pep.enforce(actor, resource_proposal, approval_id=resource_receipt.approval_id, now=NOW).reason == "approval-stale"

    policy_proposal = LAB.refund_proposal("stale:policy", 2_500)
    policy_receipt = LAB.authorize_and_approve(
        pep, actor, approver, policy_proposal, approval_id="approval:policy", now=NOW
    )
    pep.pdp.policy.version = "northwind-authz-6"
    assert pep.enforce(actor, policy_proposal, approval_id=policy_receipt.approval_id, now=NOW).reason == "approval-stale"


def test_dependency_failures_remain_errors_not_denials() -> None:
    pep, actor, _, _ = LAB.build_scenario()
    proposal = LAB.refund_proposal("dependency:pdp", 500)
    pep.pdp.available = False
    pdp_error = pep.enforce(actor, proposal, now=NOW)
    assert pdp_error.status is LAB.DecisionStatus.ERROR
    assert pdp_error.reason == "pdp-unavailable"

    pep, actor, _, _ = LAB.build_scenario()
    proposal = LAB.refund_proposal("dependency:approval", 2_500)
    pep.approvals.available = False
    store_error = pep.enforce(actor, proposal, now=NOW)
    assert store_error.status is LAB.DecisionStatus.ERROR
    assert store_error.reason == "approval-store-unavailable"
    assert not pep.effects


def test_atomic_single_use_under_concurrency() -> None:
    allowed, denied, effects = LAB.concurrency_probe(workers=8, now=NOW)
    assert (allowed, denied, effects) == (1, 7, 1)
