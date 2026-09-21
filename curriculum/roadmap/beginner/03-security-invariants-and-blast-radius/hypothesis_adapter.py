"""Deterministic Hypothesis properties for Foundation 03.

Property-based testing explores generated inputs and action sequences. It can
find counterexamples to encoded properties; it cannot prove the properties are
complete or that a distributed production deployment matches this model.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

from hypothesis import given, settings, strategies as st


CORE_SPEC = importlib.util.spec_from_file_location("foundation_03_invariant_core", Path(__file__).with_name("lab.py"))
assert CORE_SPEC and CORE_SPEC.loader
CORE = importlib.util.module_from_spec(CORE_SPEC)
sys.modules[CORE_SPEC.name] = CORE
CORE_SPEC.loader.exec_module(CORE)
ActionProposal = CORE.ActionProposal
DecisionStatus = CORE.DecisionStatus
Operation = CORE.Operation
PolicyLimits = CORE.PolicyLimits
audit_trajectory = CORE.audit_trajectory
build_runtime = CORE.build_runtime


NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
DETERMINISTIC = settings(max_examples=75, derandomize=True, database=None, deadline=None)


@DETERMINISTIC
@given(
    resource_id=st.sampled_from(("case:south:9", "ledger:global")),
    amount_cents=st.integers(min_value=0, max_value=100_000),
    claimed_subject=st.text(max_size=20),
)
def property_cross_tenant_claims_never_create_effects(
    resource_id: str,
    amount_cents: int,
    claimed_subject: str,
) -> None:
    engine, actor, _, grant = build_runtime(now=NOW)
    proposal = ActionProposal(
        Operation.ISSUE_REFUND,
        resource_id,
        "property:tenant",
        amount_cents,
        claimed_subject=claimed_subject,
        claimed_tenant="north",
    )
    decision = engine.execute(actor, proposal, grant_id=grant.grant_id, now=NOW)
    assert not decision.effect_applied
    assert decision.status is DecisionStatus.DENY
    assert not engine.state.effects


@DETERMINISTIC
@given(amounts=st.lists(st.integers(min_value=1, max_value=5_000), min_size=1, max_size=8))
def property_sequences_never_exceed_write_or_amount_budget(amounts: list[int]) -> None:
    limits = PolicyLimits(max_writes=3, max_total_cents=7_000, max_effect_cents=5_000)
    engine, actor, reviewer, grant = build_runtime(now=NOW, limits=limits)
    for index, amount in enumerate(amounts):
        proposal = ActionProposal(Operation.ISSUE_REFUND, "case:north:7", f"property:{index}", amount)
        approval_id = f"approval:property:{index}"
        engine.approvals.issue(proposal, actor, reviewer, approval_id=approval_id, now=NOW)
        engine.execute(actor, proposal, grant_id=grant.grant_id, approval_id=approval_id, now=NOW)
    assert engine.state.writes_used <= limits.max_writes
    assert engine.state.amount_used_cents <= limits.max_total_cents
    assert audit_trajectory(engine).accepted


@DETERMINISTIC
@given(claimed_tenant=st.text(max_size=20), claimed_subject=st.text(max_size=20))
def property_claimed_identity_never_changes_authority(claimed_tenant: str, claimed_subject: str) -> None:
    engine, actor, _, grant = build_runtime(now=NOW)
    proposal = ActionProposal(
        Operation.SEND_EMAIL,
        "case:north:7",
        "property:identity",
        destination="attacker.example",
        claimed_subject=claimed_subject,
        claimed_tenant=claimed_tenant,
    )
    claimed = engine.execute(actor, proposal, grant_id=grant.grant_id, now=NOW)
    blank = engine.execute(
        actor,
        replace(proposal, claimed_subject="", claimed_tenant="", logical_operation_id="property:identity:blank"),
        grant_id=grant.grant_id,
        now=NOW,
    )
    assert claimed.reason == blank.reason == "capability-operation"
    assert not claimed.effect_applied and not blank.effect_applied


def run_properties() -> dict[str, int]:
    property_cross_tenant_claims_never_create_effects()
    property_sequences_never_exceed_write_or_amount_budget()
    property_claimed_identity_never_changes_authority()
    return {"properties": 3, "generated_examples_per_property": 75}


if __name__ == "__main__":
    print(run_properties())
