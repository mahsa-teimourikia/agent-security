"""Focused regressions for Foundation 03 invariants and blast radius."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "03-security-invariants-and-blast-radius"
SPEC = importlib.util.spec_from_file_location("foundation_03_invariants", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAB
SPEC.loader.exec_module(LAB)
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


def test_model_claims_never_supply_identity_tenant_or_capability() -> None:
    engine, actor, _, grant = LAB.build_runtime(now=NOW)
    proposal = LAB.ActionProposal(
        LAB.Operation.ISSUE_REFUND,
        "case:south:9",
        "attack:claims",
        100,
        claimed_subject="admin",
        claimed_tenant="south",
    )
    decision = engine.execute(actor, proposal, grant_id=grant.grant_id, now=NOW)
    assert decision.reason == "tenant-isolation"
    assert decision.subject == actor.subject and decision.tenant == actor.tenant
    assert not decision.effect_applied


def test_exact_approval_binding_and_atomic_replay_control() -> None:
    engine, actor, reviewer, grant = LAB.build_runtime(now=NOW)
    original = LAB.valid_refund("refund:binding", 1_000)
    engine.approvals.issue(original, actor, reviewer, approval_id="approval:binding", now=NOW)
    altered = replace(original, amount_cents=1_001)
    denied = engine.execute(
        actor,
        altered,
        grant_id=grant.grant_id,
        approval_id="approval:binding",
        now=NOW,
    )
    allowed = engine.execute(
        actor,
        original,
        grant_id=grant.grant_id,
        approval_id="approval:binding",
        now=NOW,
    )
    duplicate = engine.execute(
        actor,
        original,
        grant_id=grant.grant_id,
        approval_id="approval:binding",
        now=NOW,
    )
    assert denied.reason == "approval-binding"
    assert allowed.effect_applied
    assert duplicate.status is LAB.DecisionStatus.DUPLICATE and not duplicate.effect_applied
    assert engine.state.writes_used == 1


def test_proposal_digest_is_unambiguous_and_binds_every_field() -> None:
    first = LAB.ActionProposal(LAB.Operation.ISSUE_REFUND, "case|north", "7", 100)
    delimiter_collision = LAB.ActionProposal(LAB.Operation.ISSUE_REFUND, "case", "north|7", 100)
    changed_claim = replace(first, claimed_subject="admin")
    assert LAB.proposal_digest(first) != LAB.proposal_digest(delimiter_collision)
    assert LAB.proposal_digest(first) != LAB.proposal_digest(changed_claim)


def test_approval_requires_independent_reviewer_and_rejects_unknown_or_expired_receipts() -> None:
    engine, actor, reviewer, grant = LAB.build_runtime(now=NOW)
    proposal = LAB.valid_refund("refund:approval-lifecycle", 100)
    self_reviewer = LAB.ReviewerContext(actor.subject, frozenset({"refund-approver"}))
    with pytest.raises(PermissionError, match="own effect"):
        engine.approvals.issue(proposal, actor, self_reviewer, approval_id="approval:self", now=NOW)
    engine.approvals.issue(
        proposal,
        actor,
        reviewer,
        approval_id="approval:expired",
        now=NOW,
        ttl=timedelta(seconds=1),
    )
    expired = engine.execute(
        actor,
        proposal,
        grant_id=grant.grant_id,
        approval_id="approval:expired",
        now=NOW + timedelta(seconds=1),
    )
    unknown = engine.execute(
        actor,
        replace(proposal, logical_operation_id="refund:unknown"),
        grant_id=grant.grant_id,
        approval_id="approval:forged",
        now=NOW,
    )
    assert expired.reason == "approval-time" and unknown.reason == "approval-unknown"
    assert not engine.state.effects


def test_idempotency_collision_does_not_reinterpret_changed_effect() -> None:
    engine, actor, reviewer, grant = LAB.build_runtime(now=NOW)
    original = LAB.valid_refund("refund:stable", 1_000)
    assert LAB.execute_approved(
        engine, actor, reviewer, original, grant, approval_id="approval:stable", now=NOW
    ).effect_applied
    changed = replace(original, amount_cents=2_000)
    collision = engine.execute(actor, changed, grant_id=grant.grant_id, now=NOW)
    assert collision.reason == "operation-id-collision"
    assert engine.state.writes_used == 1 and engine.state.amount_used_cents == 1_000


def test_budget_reservation_is_atomic_under_concurrency() -> None:
    limits = LAB.PolicyLimits(max_writes=1, max_total_cents=1_000, max_effect_cents=1_000)
    engine, actor, reviewer, grant = LAB.build_runtime(now=NOW, limits=limits)
    proposals = [LAB.valid_refund(f"refund:concurrent:{index}", 1_000) for index in range(8)]
    for index, proposal in enumerate(proposals):
        engine.approvals.issue(proposal, actor, reviewer, approval_id=f"approval:{index}", now=NOW)

    def invoke(item: tuple[int, object]):
        index, proposal = item
        return engine.execute(
            actor,
            proposal,
            grant_id=grant.grant_id,
            approval_id=f"approval:{index}",
            now=NOW,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(invoke, enumerate(proposals)))
    assert sum(item.effect_applied for item in decisions) == 1
    assert sum(item.reason == "write-budget" for item in decisions) == 7
    assert LAB.audit_trajectory(engine).accepted


def test_kill_switch_blocks_new_effects_without_erasing_prior_evidence() -> None:
    engine, actor, reviewer, grant = LAB.build_runtime(now=NOW)
    first = LAB.execute_approved(
        engine,
        actor,
        reviewer,
        LAB.valid_refund("refund:before", 500),
        grant,
        approval_id="approval:before",
        now=NOW,
    )
    engine.activate_kill_switch(at=NOW + timedelta(seconds=1))
    after = LAB.valid_refund("refund:after", 500)
    engine.approvals.issue(after, actor, reviewer, approval_id="approval:after", now=NOW)
    denied = engine.execute(
        actor,
        after,
        grant_id=grant.grant_id,
        approval_id="approval:after",
        now=NOW + timedelta(seconds=1),
    )
    assert first.effect_applied and denied.reason == "kill-switch"
    assert len(engine.state.effects) == 1
    assert LAB.audit_trajectory(engine).accepted


def test_revoked_and_stale_policy_capabilities_cannot_start_effects() -> None:
    engine, actor, _, grant = LAB.build_runtime(now=NOW)
    for label, changed, reason in (
        ("revoked", replace(grant, revoked=True), "capability-revoked"),
        ("stale", replace(grant, policy_version="old"), "capability-policy"),
    ):
        engine.capabilities.grants[grant.grant_id] = changed
        decision = engine.execute(
            actor,
            LAB.valid_refund(f"refund:{label}", 100),
            grant_id=grant.grant_id,
            now=NOW,
        )
        assert decision.reason == reason and not decision.effect_applied


@pytest.mark.parametrize(
    ("approval_available", "capability_available", "expected"),
    ((False, True, "approval-service-unavailable"), (True, False, "capability-service-unavailable")),
)
def test_authority_dependency_failures_do_not_become_success(
    approval_available: bool,
    capability_available: bool,
    expected: str,
) -> None:
    engine, actor, _, grant = LAB.build_runtime(
        now=NOW,
        approval_available=approval_available,
        capability_available=capability_available,
    )
    decision = engine.execute(
        actor,
        LAB.valid_refund("failure:dependency", 100),
        grant_id=grant.grant_id,
        approval_id="approval:any",
        now=NOW,
    )
    assert decision.reason == expected
    assert not decision.effect_applied and not engine.state.effects


def test_blast_radius_is_a_vector_and_bounded_profile_is_strictly_narrower() -> None:
    profiles = LAB.blast_radius_profiles(now=NOW)
    broad, bounded, deny_all = profiles["broad"], profiles["bounded"], profiles["deny_all"]
    assert broad.tenants == 3 and bounded.tenants == 1 and deny_all.tenants == 0
    assert broad.resources > bounded.resources > deny_all.resources
    assert broad.max_writes_per_run > bounded.max_writes_per_run > deny_all.max_writes_per_run
    assert broad.egress_destinations > bounded.egress_destinations == deny_all.egress_destinations == 0


def test_evaluation_separates_attack_effects_from_valid_task_utility() -> None:
    report, cases = LAB.evaluate_controls(now=NOW)
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (12, 3, 7, 2)
    assert report.attack_effect_rate == report.valid_task_block_rate == 0
    assert report.attack_block_rate == report.valid_task_success_rate == 1
    assert report.trace_completeness_rate == 1
    assert report.unsafe_baseline_attack_acceptance_rate == 1
    assert report.deny_all_valid_task_success_rate == 0
    assert all(case.decision.successful == case.expected_success for case in cases)


def test_architecture_diagram_is_validated_and_deterministic() -> None:
    render_spec = importlib.util.spec_from_file_location("foundation_03_diagram", COURSE / "render_architecture.py")
    assert render_spec and render_spec.loader
    renderer = importlib.util.module_from_spec(render_spec)
    sys.modules[render_spec.name] = renderer
    render_spec.loader.exec_module(renderer)
    spec = json.loads((COURSE / "architecture-spec.json").read_text())
    renderer.validate(spec)
    assert renderer.render(spec) == (COURSE / "architecture.svg").read_text()
