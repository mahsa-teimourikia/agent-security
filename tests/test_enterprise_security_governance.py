"""Invariant tests for Enterprise Course 06 security governance."""
from dataclasses import asdict, replace
import importlib.util
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/06-agent-security-governance"
sys.path.insert(0, str(ROOT))
import governance as gov  # noqa: E402
import governance_fixtures as fx  # noqa: E402
import governance_pydantic_adapter as adapter  # noqa: E402


def test_happy_path_is_ready_and_authorizes_once():
    record = fx.record()
    engine = fx.engine()
    decision = engine.evaluate(record, gov.Lifecycle.AUTHORIZED, fx.NOW)
    assert decision.state is gov.DecisionState.READY
    updated = engine.authorize(record, decision, fx.approval(decision), fx.operator(), fx.NOW)
    assert (updated.lifecycle, updated.revision) == (gov.Lifecycle.AUTHORIZED, 8)
    with pytest.raises(PermissionError, match="approval-replayed"):
        engine.authorize(record, decision, fx.approval(decision), fx.operator(), fx.NOW)


@pytest.mark.parametrize("kind", ["threat-model", "security-test", "privacy-review", "incident-drill"])
def test_each_required_evidence_kind_is_enforced(kind):
    items = [fx.evidence(value) for value in fx.KINDS if value != kind]
    decision = fx.engine(items).evaluate(fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW)
    assert f"missing-evidence:{kind}" in decision.blockers


@pytest.mark.parametrize("risk,required", [
    (gov.RiskTier.LOW, 2), (gov.RiskTier.MEDIUM, 3),
    (gov.RiskTier.HIGH, 4), (gov.RiskTier.CRITICAL, 5)])
def test_risk_tier_changes_evidence_depth(risk, required):
    decision = fx.engine([]).evaluate(fx.record(risk_tier=risk), gov.Lifecycle.AUTHORIZED, fx.NOW)
    assert len([item for item in decision.blockers if item.startswith("missing-evidence:")]) == required


def test_stale_record_revision_cannot_reuse_evidence():
    decision = fx.engine().evaluate(fx.record(revision=8), gov.Lifecycle.AUTHORIZED, fx.NOW)
    assert decision.state is gov.DecisionState.INCOMPLETE


@pytest.mark.parametrize("field,value,blocker", [
    ("tenant", "south", "producer-scope"),
    ("key_id", "unknown", "producer-scope"),
    ("kind", "self-attestation", "producer-kind"),
    ("checked", 0, "invalid-counts"),
    ("created_at", 1_001, "invalid-time")])
def test_evidence_admission_rejects_invalid_scope(field, value, blocker):
    store = fx.store([])
    unsigned = replace(fx.evidence("security-test"), **{field: value}, proof="")
    if field != "key_id":
        unsigned = fx.keyring().sign(unsigned)
    assert store.admit(unsigned, fx.NOW).reason == blocker


def test_tampered_evidence_is_rejected():
    item = replace(fx.evidence("security-test"), passed=99)
    assert fx.store([]).admit(item, fx.NOW).reason == "invalid-proof"


def test_duplicate_delivery_is_idempotent_but_conflict_is_rejected():
    store = fx.store([])
    item = fx.evidence("security-test")
    assert store.admit(item, fx.NOW).admitted
    assert store.admit(item, fx.NOW).admitted
    conflict = fx.evidence("security-test", passed=99)
    assert store.admit(conflict, fx.NOW).reason == "delivery-conflict"


@pytest.mark.parametrize("change,blocker", [
    ({"expires_at": 999}, "expired-evidence:security-test"),
    ({"passed": 99}, "failed-evidence:security-test"),
    ({"severe_failures": 1}, "severe-failure")])
def test_bad_security_evidence_blocks(change, blocker):
    item = fx.evidence("security-test", **change)
    others = [fx.evidence(kind) for kind in ("threat-model", "privacy-review", "incident-drill")]
    decision = fx.engine([item, *others]).evaluate(fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW)
    assert blocker in decision.blockers


def test_high_risk_requires_kill_switch_owner():
    decision = fx.engine().evaluate(fx.record(kill_switch_owner=""), gov.Lifecycle.AUTHORIZED, fx.NOW)
    assert "missing-kill-switch-owner" in decision.blockers


def test_review_due_date_is_enforced():
    decision = fx.engine().evaluate(fx.record(review_due_at=999), gov.Lifecycle.AUTHORIZED, fx.NOW)
    assert "review-overdue" in decision.blockers


def test_valid_exception_waives_only_named_compensable_blocker():
    decision = fx.engine().evaluate(
        fx.record(review_due_at=999), gov.Lifecycle.AUTHORIZED, fx.NOW,
        [fx.exception("review-overdue")])
    assert decision.state is gov.DecisionState.READY
    assert decision.waived == ("review-overdue",)


@pytest.mark.parametrize("change", [
    {"expires_at": 999}, {"tenant": "south"}, {"record_revision": 6}, {"owner": ""}])
def test_invalid_exception_does_not_waive(change):
    grant = fx.exception("review-overdue", **change)
    decision = fx.engine().evaluate(fx.record(review_due_at=999), gov.Lifecycle.AUTHORIZED, fx.NOW, [grant])
    assert "review-overdue" in decision.blockers


def test_exception_tamper_is_rejected():
    grant = replace(fx.exception("review-overdue"), blocker="severe-failure")
    decision = fx.engine().evaluate(fx.record(review_due_at=999), gov.Lifecycle.AUTHORIZED, fx.NOW, [grant])
    assert "review-overdue" in decision.blockers


def test_severe_failure_is_non_waivable():
    item = fx.evidence("security-test", severe_failures=1)
    others = [fx.evidence(kind) for kind in ("threat-model", "privacy-review", "incident-drill")]
    decision = fx.engine([item, *others]).evaluate(
        fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW, [fx.exception("severe-failure")])
    assert "severe-failure" in decision.blockers


@pytest.mark.parametrize("change", [
    {"tenant": "south"}, {"authorized_until": 1_000}, {"roles": frozenset()}])
def test_operator_authority_is_current_and_scoped(change):
    engine = fx.engine()
    decision = engine.evaluate(fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW)
    with pytest.raises(PermissionError, match="operator-not-authorized"):
        engine.authorize(fx.record(), decision, fx.approval(decision), fx.operator(**change), fx.NOW)


def test_approver_and_operator_are_separate():
    engine = fx.engine()
    decision = engine.evaluate(fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW)
    with pytest.raises(PermissionError, match="approval-scope"):
        engine.authorize(fx.record(), decision, fx.approval(decision), fx.operator(subject="security-director"), fx.NOW)


@pytest.mark.parametrize("change", [
    {"tenant": "south"}, {"record_revision": 6},
    {"expires_at": 1_000}, {"decision_digest": "wrong"}])
def test_approval_is_exact_and_current(change):
    engine = fx.engine()
    decision = engine.evaluate(fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW)
    with pytest.raises(PermissionError, match="approval-scope"):
        engine.authorize(fx.record(), decision, fx.approval(decision, **change), fx.operator(), fx.NOW)


def test_approval_tamper_is_rejected():
    engine = fx.engine()
    decision = engine.evaluate(fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW)
    approval = replace(fx.approval(decision), proof="bad")
    with pytest.raises(PermissionError, match="approval-proof"):
        engine.authorize(fx.record(), decision, approval, fx.operator(), fx.NOW)


def test_blocked_decision_cannot_be_authorized():
    engine = fx.engine([])
    decision = engine.evaluate(fx.record(), gov.Lifecycle.AUTHORIZED, fx.NOW)
    with pytest.raises(PermissionError, match="decision-not-ready"):
        engine.authorize(fx.record(), decision, fx.approval(decision), fx.operator(), fx.NOW)


def test_retired_is_terminal():
    decision = fx.engine().evaluate(fx.record(lifecycle=gov.Lifecycle.RETIRED), gov.Lifecycle.PILOT, fx.NOW)
    assert "retired-is-terminal" in decision.blockers


def test_inventory_optimistic_concurrency_rejects_stale_writer():
    inventory = gov.Inventory()
    inventory.put(fx.record(revision=1), None)
    inventory.put(fx.record(revision=2), 1)
    with pytest.raises(RuntimeError, match="revision-conflict"):
        inventory.put(fx.record(revision=2, purpose="stale overwrite"), 1)


def test_pydantic_adapter_rejects_unknown_fields_and_coercion():
    payload = asdict(fx.record())
    payload["model_generated_approval"] = True
    with pytest.raises(ValidationError):
        adapter.parse_record(payload)
    payload = asdict(fx.record())
    payload["revision"] = "7"
    with pytest.raises(ValidationError):
        adapter.parse_record(payload)


def test_pydantic_adapter_rejects_empty_required_collection():
    payload = asdict(fx.record())
    payload["models"] = ()
    with pytest.raises(ValidationError):
        adapter.parse_record(payload)


def test_lab_runs():
    spec = importlib.util.spec_from_file_location("enterprise_06_lab", ROOT / "lab.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.run_lab()["authorized_revision"] == 8
