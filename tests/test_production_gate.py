"""Focused adversarial tests for Advanced 03 production readiness."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
NOW = datetime(2026, 9, 20, tzinfo=timezone.utc)


def load_module():
    path = ROOT / "curriculum/advanced/03-production-gate/03_production_gate.py"
    spec = importlib.util.spec_from_file_location("advanced_03_production_gate_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def production():
    return load_module()


def scenario(production):
    return production.build_scenario(now=NOW)


def resign(production, envelope, payload):
    producer = production.artifact_for(payload).producer
    return production.attest_evidence(payload, production.DEMO_PRODUCER_KEYS[producer])


def replace_kind(production, evidence, kind, mutation, *, resign_payload=True):
    changed = list(evidence)
    index = next(
        index
        for index, envelope in enumerate(changed)
        if production.artifact_for(envelope.payload).kind == kind
    )
    original = changed[index]
    payload = mutation(original.payload)
    changed[index] = resign(production, original, payload) if resign_payload else replace(original, payload=payload)
    return changed


def test_complete_authentic_dossier_is_ready(production):
    gate, candidate, evidence, risks, _ = scenario(production)
    decision = gate.evaluate(candidate, evidence, risks, now=NOW)
    assert decision.state is production.DecisionState.READY
    assert decision.ready and gate.verify_decision(decision)
    assert len(decision.evidence_ids) == len(gate.policy.requirements)


@pytest.mark.parametrize("failure", ["missing", "duplicate-kind", "tampered", "wrong-subject", "stale", "producer-error"])
def test_untrustworthy_or_incomplete_evidence_never_becomes_a_failure_result(production, failure):
    gate, candidate, evidence, risks, _ = scenario(production)
    if failure == "missing":
        evidence = evidence[1:]
    elif failure == "duplicate-kind":
        evidence = [*evidence, evidence[0]]
    elif failure == "tampered":
        evidence = replace_kind(
            production,
            evidence,
            "threat-model",
            lambda payload: replace(payload, artifact=replace(payload.artifact, owner="attacker")),
            resign_payload=False,
        )
    elif failure == "wrong-subject":
        evidence = replace_kind(
            production,
            evidence,
            "policy-tests",
            lambda payload: replace(payload, artifact=replace(payload.artifact, subject_digest=production._digest("other"))),
        )
    elif failure == "stale":
        evidence = replace_kind(
            production,
            evidence,
            "control-owner",
            lambda payload: replace(payload, artifact=replace(payload.artifact, observed_at=NOW - timedelta(days=31))),
        )
    else:
        evidence = replace_kind(
            production,
            evidence,
            "artifact-provenance",
            lambda payload: replace(payload, artifact=replace(payload.artifact, result=production.EvidenceResult.ERROR)),
        )
    decision = gate.evaluate(candidate, evidence, risks, now=NOW)
    assert decision.state is production.DecisionState.INCOMPLETE
    assert any(item.startswith("incomplete:") for item in decision.blockers)


def test_severe_attack_success_is_a_non_waivable_blocker(production):
    gate, candidate, evidence, risks, _ = scenario(production)
    evidence = replace_kind(
        production,
        evidence,
        "attack-evaluation",
        lambda payload: replace(payload, severe_attack_successes=1),
    )
    decision = gate.evaluate(candidate, evidence, risks, now=NOW)
    assert decision.state is production.DecisionState.BLOCKED
    assert "blocked:severe-attack-successes:1" in decision.blockers


@pytest.mark.parametrize(
    ("kind", "mutation", "blocker"),
    [
        (
            "attack-evaluation",
            lambda module, payload: replace(payload, executed_attempts=23),
            "incomplete:attack-coverage:23/24",
        ),
        (
            "attack-evaluation",
            lambda module, payload: replace(payload, harness_errors=1),
            "incomplete:attack-harness-errors:1",
        ),
        (
            "trace-coverage",
            lambda module, payload: replace(payload, traced_critical_operations=11),
            "blocked:critical-trace-coverage:11/12",
        ),
        (
            "rollback-drill",
            lambda module, payload: replace(payload, recovery_point_verified=False),
            "blocked:rollback-recovery-point",
        ),
        (
            "rollback-drill",
            lambda module, payload: replace(payload, duration_seconds=901),
            "blocked:rollback-duration:901/900",
        ),
    ],
)
def test_structured_evidence_preserves_denominators_and_failure_meaning(production, kind, mutation, blocker):
    gate, candidate, evidence, risks, _ = scenario(production)
    evidence = replace_kind(production, evidence, kind, lambda payload: mutation(production, payload))
    decision = gate.evaluate(candidate, evidence, risks, now=NOW)
    assert blocker in decision.blockers


def test_expired_or_tampered_risk_acceptance_is_incomplete(production):
    gate, candidate, evidence, risks, _ = scenario(production)
    expired_payload = replace(risks[0].payload, expires_at=NOW)
    expired = production.attest_risk(expired_payload, production.DEMO_HUMAN_KEYS[expired_payload.approver])
    assert gate.evaluate(candidate, evidence, [expired], now=NOW).state is production.DecisionState.INCOMPLETE
    tampered = replace(risks[0], payload=replace(risks[0].payload, rationale="silently changed"))
    assert gate.evaluate(candidate, evidence, [tampered], now=NOW).state is production.DecisionState.INCOMPLETE


def test_duplicate_risk_acceptance_id_is_ambiguous(production):
    gate, candidate, evidence, risks, _ = scenario(production)
    decision = gate.evaluate(candidate, evidence, [risks[0], risks[0]], now=NOW)
    assert decision.state is production.DecisionState.INCOMPLETE
    assert "incomplete:duplicate-risk-acceptance-id:RA-12" in decision.blockers


def ready_authorization(production):
    gate, candidate, evidence, risks, approver = scenario(production)
    decision = gate.evaluate(candidate, evidence, risks, now=NOW)
    result = gate.authorize_deployment(
        decision,
        candidate,
        approver,
        authorization_id="DA-test",
        now=NOW + timedelta(minutes=1),
    )
    assert result.allowed and result.authorization
    return gate, candidate, decision, result.authorization


def test_release_approver_must_be_current_and_independent(production):
    gate, candidate, evidence, risks, _ = scenario(production)
    decision = gate.evaluate(candidate, evidence, risks, now=NOW)
    self_approver = production.ActorContext(candidate.requested_by, candidate.tenant)
    result = gate.authorize_deployment(
        decision,
        candidate,
        self_approver,
        authorization_id="DA-self",
        now=NOW + timedelta(minutes=1),
    )
    assert not result.allowed and result.reason == "approver-independence"

    unknown = production.ActorContext("unknown:operator", candidate.tenant)
    unauthorized = gate.authorize_deployment(
        decision,
        candidate,
        unknown,
        authorization_id="DA-unknown",
        now=NOW + timedelta(minutes=1),
    )
    assert not unauthorized.allowed and unauthorized.reason == "approver-role"


def test_authorization_is_bound_to_candidate_and_current_policy(production):
    gate, candidate, _, authorization = ready_authorization(production)
    ledger = production.DeploymentLedger(gate)
    changed = replace(candidate, artifact_digest=production._digest("changed-candidate"))
    assert ledger.consume(
        authorization,
        changed,
        current_policy_version=gate.policy.version,
        now=NOW + timedelta(minutes=2),
    ).reason == "authorization-binding"
    changed_prompt = replace(candidate, prompt_version="support-prompt/v10")
    assert ledger.consume(
        authorization,
        changed_prompt,
        current_policy_version=gate.policy.version,
        now=NOW + timedelta(minutes=2),
    ).reason == "authorization-binding"
    changed_source = replace(candidate, source_revision="git:changed")
    assert ledger.consume(
        authorization,
        changed_source,
        current_policy_version=gate.policy.version,
        now=NOW + timedelta(minutes=2),
    ).reason == "authorization-binding"
    assert ledger.consume(
        authorization,
        candidate,
        current_policy_version="release-policy/v4",
        now=NOW + timedelta(minutes=2),
    ).reason == "policy-version"


def test_single_use_authorization_is_consumed_atomically(production):
    gate, candidate, _, authorization = ready_authorization(production)
    ledger = production.DeploymentLedger(gate)

    def consume(_):
        return ledger.consume(
            authorization,
            candidate,
            current_policy_version=gate.policy.version,
            now=NOW + timedelta(minutes=2),
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = list(pool.map(consume, range(8)))
    assert sum(receipt.allowed for receipt in receipts) == 1
    assert sum(receipt.reason == "authorization-replayed" for receipt in receipts) == 7


def test_tampered_or_expired_authorization_is_denied(production):
    gate, candidate, _, authorization = ready_authorization(production)
    ledger = production.DeploymentLedger(gate)
    tampered = replace(authorization, environment="staging")
    assert ledger.consume(
        tampered,
        candidate,
        current_policy_version=gate.policy.version,
        now=NOW + timedelta(minutes=2),
    ).reason == "invalid-authorization"
    assert ledger.consume(
        authorization,
        candidate,
        current_policy_version=gate.policy.version,
        now=authorization.expires_at,
    ).reason == "authorization-expired"
