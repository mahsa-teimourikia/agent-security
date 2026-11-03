"""Invariant tests for Enterprise Course 05 release readiness."""
from __future__ import annotations

from dataclasses import asdict, replace
import importlib.util
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


COURSE = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/05-security-release-gates-and-production-readiness"
sys.path.insert(0, str(COURSE))

import release_fixtures as fixtures  # noqa: E402
import pydantic_adapter as adapter  # noqa: E402
import release_readiness as rr  # noqa: E402

LAB_SPEC = importlib.util.spec_from_file_location("enterprise_05_release_lab", COURSE / "lab.py")
assert LAB_SPEC and LAB_SPEC.loader
lab = importlib.util.module_from_spec(LAB_SPEC)
sys.modules[LAB_SPEC.name] = lab
LAB_SPEC.loader.exec_module(lab)


def evaluate(scenario: fixtures.CourseScenario, *, now: int = 120, exceptions=()):
    return scenario.gate.evaluate(
        release_digest=scenario.record.candidate_digest,
        tenant=scenario.record.tenant,
        environment=scenario.record.environment,
        policy_version=scenario.executor.current_policy_version,
        now=now,
        exceptions=exceptions,
    )


def execute(scenario: fixtures.CourseScenario, **changes):
    exceptions = changes.get("exceptions", ())
    _, plan, approval = fixtures.approved_release(scenario, exceptions=exceptions)
    return scenario.executor.execute(
        scenario.record,
        changes.get("plan", plan),
        changes.get("approval", approval),
        changes.get("actor", scenario.actor),
        changes.get("authorizer", scenario.authorizer),
        scenario.provider,
        now=changes.get("now", 120),
        exceptions=exceptions,
    )


def test_canonical_digest_preserves_sequence_and_normalizes_sets():
    assert rr.digest(["a", "b"]) != rr.digest(["b", "a"])
    assert rr.digest(frozenset({"a", "b"})) == rr.digest(frozenset({"b", "a"}))


def test_pydantic_adapter_parses_a_signed_json_shaped_payload():
    scenario = fixtures.build_scenario()
    item = next(iter(scenario.store.evidence.values()))
    payload = asdict(item)
    payload["kind"] = item.kind.value
    payload["result"] = item.result.value
    assert adapter.parse_evidence(payload) == item


@pytest.mark.parametrize("mutation", [
    {"unexpected": "field"},
    {"checked": "100"},
    {"kind": "not-a-kind"},
    {"owner": ""},
])
def test_pydantic_adapter_rejects_extra_coerced_invalid_or_empty_fields(mutation):
    item = fixtures.make_evidence(adapter.fixture_keyring())[0]
    payload = asdict(item)
    payload["kind"] = item.kind.value
    payload["result"] = item.result.value
    payload.update(mutation)
    with pytest.raises(ValidationError):
        adapter.parse_evidence(payload)


def test_schema_validation_does_not_establish_producer_trust():
    item = fixtures.make_evidence(adapter.fixture_keyring())[0]
    parsed = adapter.parse_evidence({
        **asdict(item), "kind": item.kind.value, "result": item.result.value,
    })
    store = rr.EvidenceStore({}, adapter.fixture_keyring())
    assert store.admit(parsed, now=120).reason == "producer-not-trusted"


def test_admits_complete_authenticated_evidence():
    keyring = adapter.fixture_keyring()
    item = fixtures.make_evidence(keyring)[0]
    producer = rr.TrustedProducer("ci:north", "north", "ci-evidence-2026-11", fixtures.ALL_KINDS)
    store = rr.EvidenceStore({producer.producer_id: producer}, keyring)
    assert store.admit(item, now=120).status is rr.Admission.ADMITTED


def test_identical_delivery_is_idempotent():
    scenario = fixtures.build_scenario()
    item = next(iter(scenario.store.evidence.values()))
    assert scenario.store.admit(item, now=120).status is rr.Admission.IDEMPOTENT


def test_same_evidence_id_with_changed_content_is_quarantined():
    scenario = fixtures.build_scenario()
    item = next(iter(scenario.store.evidence.values()))
    changed = scenario.keyring.sign_evidence(replace(item, passed=0, proof=""), item.key_id)
    assert scenario.store.admit(changed, now=120).reason == "evidence-id-conflict"


@pytest.mark.parametrize(("changes", "reason"), [
    ({"producer_id": "unknown"}, "producer-not-trusted"),
    ({"key_id": "release-board-2026-11"}, "producer-key-mismatch"),
    ({"tenant": "south"}, "producer-tenant-mismatch"),
    ({"proof": "00"}, "invalid-evidence-proof"),
])
def test_untrusted_producer_key_tenant_or_proof_is_quarantined(changes, reason):
    scenario = fixtures.build_scenario()
    original = next(iter(scenario.store.evidence.values()))
    candidate = replace(original, evidence_id="evidence:new", **changes)
    assert scenario.store.admit(candidate, now=120).reason == reason


def test_producer_cannot_issue_an_unregistered_evidence_kind():
    keyring = adapter.fixture_keyring()
    item = fixtures.make_evidence(keyring)[0]
    producer = rr.TrustedProducer(
        "ci:north", "north", "ci-evidence-2026-11",
        frozenset({rr.EvidenceKind.UNIT_TEST}),
    )
    store = rr.EvidenceStore({producer.producer_id: producer}, keyring)
    assert store.admit(item, now=120).reason == "producer-kind-not-allowed"


@pytest.mark.parametrize(("changes", "reason"), [
    ({"checked": 0}, "invalid-evidence-fields"),
    ({"passed": 2, "checked": 1}, "invalid-evidence-fields"),
    ({"owner": ""}, "invalid-evidence-fields"),
    ({"severe_failures": -1}, "invalid-severe-failure-count"),
    ({"issued_at": 121}, "invalid-evidence-time"),
    ({"expires_at": 100}, "invalid-evidence-time"),
])
def test_invalid_counts_ownership_and_time_are_quarantined(changes, reason):
    keyring = adapter.fixture_keyring()
    original = fixtures.make_evidence(keyring)[0]
    candidate = replace(original, evidence_id="evidence:new", **changes, proof="")
    candidate = keyring.sign_evidence(candidate, "ci-evidence-2026-11")
    producer = rr.TrustedProducer("ci:north", "north", "ci-evidence-2026-11", fixtures.ALL_KINDS)
    store = rr.EvidenceStore({producer.producer_id: producer}, keyring)
    assert store.admit(candidate, now=120).reason == reason


def test_complete_current_exact_dossier_is_ready():
    decision = evaluate(fixtures.build_scenario())
    assert decision.state is rr.GateState.READY
    assert decision.evidence_coverage == 1.0 and decision.oldest_evidence_age == 20
    assert len(decision.evidence_ids) == len(rr.EvidenceKind)


def test_missing_required_evidence_is_incomplete():
    scenario = fixtures.build_scenario()
    scenario.store.evidence.pop("evidence:rollback-drill:500")
    decision = evaluate(scenario)
    assert decision.state is rr.GateState.INCOMPLETE
    assert "missing:rollback-drill" in decision.blockers


def test_cross_release_evidence_does_not_fill_current_dossier():
    scenario = fixtures.build_scenario()
    scenario.record.candidate_digest = "sha256:different-501"
    decision = evaluate(scenario)
    assert decision.state is rr.GateState.INCOMPLETE
    assert len(decision.evidence_ids) == 0


def test_duplicate_evidence_kind_is_not_resolved_by_arbitrary_order():
    scenario = fixtures.build_scenario()
    original = scenario.store.evidence["evidence:unit-test:500"]
    duplicate = scenario.keyring.sign_evidence(
        replace(original, evidence_id="evidence:unit-test:duplicate", proof=""),
        original.key_id,
    )
    assert scenario.store.admit(duplicate, now=120).status is rr.Admission.ADMITTED
    assert "duplicate-kind:unit-test" in evaluate(scenario).blockers


def test_stale_evidence_is_not_made_current_by_presence():
    decision = evaluate(fixtures.build_scenario(), now=401)
    assert decision.state is not rr.GateState.READY
    assert any(reason.startswith("stale:") for reason in decision.blockers)


def test_policy_version_mismatch_blocks_release():
    scenario = fixtures.build_scenario()
    scenario.executor.current_policy_version = "release-policy-2026-12"
    assert any(reason.startswith("policy-mismatch:") for reason in evaluate(scenario).blockers)


@pytest.mark.parametrize(("result", "state", "prefix"), [
    (rr.EvidenceResult.FAIL, rr.GateState.BLOCKED, "failed:"),
    (rr.EvidenceResult.INCONCLUSIVE, rr.GateState.INCOMPLETE, "inconclusive:"),
])
def test_failure_and_inconclusive_are_distinct_non_ready_states(result, state, prefix):
    scenario = fixtures.build_scenario()
    key = "evidence:integration-test:500"
    original = scenario.store.evidence[key]
    changed = scenario.keyring.sign_evidence(
        replace(original, result=result, proof=""), original.key_id,
    )
    scenario.store.evidence[key] = changed
    scenario.store.evidence_digests[key] = rr.digest(rr.evidence_payload(changed))
    decision = evaluate(scenario)
    assert decision.state is state
    assert any(reason.startswith(prefix) for reason in decision.blockers)


def test_low_coverage_blocks_even_when_result_says_pass():
    scenario = fixtures.build_scenario()
    key = "evidence:integration-test:500"
    scenario.store.evidence[key] = replace(scenario.store.evidence[key], checked=100, passed=1)
    assert "coverage:integration-test" in evaluate(scenario).blockers


def test_one_severe_failure_cannot_be_averaged_away():
    scenario = fixtures.build_scenario()
    key = "evidence:adversarial-eval:500"
    scenario.store.evidence[key] = replace(scenario.store.evidence[key], severe_failures=1)
    decision = evaluate(scenario)
    assert decision.severe_failures == 1
    assert decision.state is rr.GateState.BLOCKED
    assert "severe-failure" in decision.blockers


def test_known_severe_failure_takes_precedence_over_missing_evidence():
    scenario = fixtures.build_scenario()
    scenario.store.evidence.pop("evidence:rollback-drill:500")
    key = "evidence:adversarial-eval:500"
    original = scenario.store.evidence[key]
    changed = scenario.keyring.sign_evidence(
        replace(original, severe_failures=1, proof=""), original.key_id,
    )
    scenario.store.evidence[key] = changed
    scenario.store.evidence_digests[key] = rr.digest(rr.evidence_payload(changed))
    decision = evaluate(scenario)
    assert decision.state is rr.GateState.BLOCKED
    assert "severe-failure" in decision.blockers
    assert "missing:rollback-drill" in decision.blockers


def test_post_admission_tampering_is_reverified_at_gate_time():
    scenario = fixtures.build_scenario()
    key = "evidence:adversarial-eval:500"
    scenario.store.evidence[key] = replace(
        scenario.store.evidence[key], result=rr.EvidenceResult.PASS, severe_failures=0,
        payload_digest="forged-passing-report",
    )
    assert "tampered:adversarial-eval" in evaluate(scenario).blockers


def test_valid_exception_can_waive_only_its_exact_waivable_blocker():
    scenario = fixtures.build_scenario()
    key = "evidence:unit-test:500"
    original = scenario.store.evidence[key]
    changed = scenario.keyring.sign_evidence(
        replace(original, checked=100, passed=98, proof=""), original.key_id,
    )
    scenario.store.evidence[key] = changed
    scenario.store.evidence_digests[key] = rr.digest(rr.evidence_payload(changed))
    exception = fixtures.signed_exception(scenario, "coverage:unit-test")
    decision = evaluate(scenario, exceptions=(exception,))
    assert decision.state is rr.GateState.READY
    assert decision.waived_blockers == ("coverage:unit-test",)


def test_effective_exception_is_bound_into_plan_and_rechecked_at_execution():
    scenario = fixtures.build_scenario()
    key = "evidence:unit-test:500"
    original = scenario.store.evidence[key]
    changed = scenario.keyring.sign_evidence(
        replace(original, checked=100, passed=98, proof=""), original.key_id,
    )
    scenario.store.evidence[key] = changed
    scenario.store.evidence_digests[key] = rr.digest(rr.evidence_payload(changed))
    exception = fixtures.signed_exception(scenario, "coverage:unit-test")
    decision, plan, approval = fixtures.approved_release(scenario, exceptions=(exception,))
    assert decision.state is rr.GateState.READY
    assert plan.exception_set_digest == decision.exception_set_digest
    result = scenario.executor.execute(
        scenario.record, plan, approval, scenario.actor, scenario.authorizer,
        scenario.provider, now=120, exceptions=(exception,),
    )
    assert result.state is rr.ReleaseState.PROMOTED


def test_omitting_plan_bound_exception_at_execution_blocks_rollout():
    scenario = fixtures.build_scenario()
    key = "evidence:unit-test:500"
    original = scenario.store.evidence[key]
    changed = scenario.keyring.sign_evidence(
        replace(original, checked=100, passed=98, proof=""), original.key_id,
    )
    scenario.store.evidence[key] = changed
    scenario.store.evidence_digests[key] = rr.digest(rr.evidence_payload(changed))
    exception = fixtures.signed_exception(scenario, "coverage:unit-test")
    _, plan, approval = fixtures.approved_release(scenario, exceptions=(exception,))
    result = scenario.executor.execute(
        scenario.record, plan, approval, scenario.actor, scenario.authorizer,
        scenario.provider, now=120,
    )
    assert result.reason == "release-gate-blocked"
    assert scenario.provider.deployment_effects == 0


def test_severe_failure_is_non_waivable_even_with_signed_exception():
    scenario = fixtures.build_scenario()
    key = "evidence:adversarial-eval:500"
    original = scenario.store.evidence[key]
    changed = scenario.keyring.sign_evidence(
        replace(original, severe_failures=1, proof=""), original.key_id,
    )
    scenario.store.evidence[key] = changed
    scenario.store.evidence_digests[key] = rr.digest(rr.evidence_payload(changed))
    exception = fixtures.signed_exception(scenario, "severe-failure")
    decision = evaluate(scenario, exceptions=(exception,))
    assert "severe-failure" in decision.blockers
    assert "non-waivable:severe-failure" in decision.blockers


def test_expired_exception_is_rejected():
    scenario = fixtures.build_scenario()
    exception = fixtures.signed_exception(scenario, "coverage:unit-test", now=50)
    assert any(reason.startswith("invalid-exception:") for reason in evaluate(scenario, exceptions=(exception,)).blockers)


def test_safe_canary_is_promoted_and_verified():
    scenario = fixtures.build_scenario()
    result = execute(scenario)
    assert result.reason == "promoted-and-verified"
    assert result.state is rr.ReleaseState.PROMOTED
    assert result.deployment_verified and scenario.provider.deployment_effects == 1


def test_unsafe_canary_rolls_back_to_verified_stable_digest():
    scenario = fixtures.build_scenario()
    scenario.provider.metrics[scenario.record.candidate_digest] = rr.CanaryMetrics(100, 1, 0.0, 1.0, 400, 0.05)
    result = execute(scenario)
    assert result.state is rr.ReleaseState.ROLLED_BACK
    assert result.rollback_verified and scenario.provider.rollback_effects == 1


def test_missing_canary_metrics_triggers_verified_rollback():
    scenario = fixtures.build_scenario()
    scenario.provider.metrics.clear()
    result = execute(scenario)
    assert result.reason == "canary-metrics-incomplete"
    assert result.state is rr.ReleaseState.ROLLED_BACK


@pytest.mark.parametrize("metrics", [
    rr.CanaryMetrics(100, 0, float("nan"), 1.0, 400, 0.05),
    rr.CanaryMetrics(100, 0, 0.01, float("nan"), 400, 0.05),
    rr.CanaryMetrics(100, -1, 0.01, 1.0, 400, 0.05),
    rr.CanaryMetrics(100, 0, 0.01, 1.0, -1, 0.05),
])
def test_malformed_or_non_finite_metrics_fail_safe(metrics):
    scenario = fixtures.build_scenario()
    scenario.provider.metrics[scenario.record.candidate_digest] = metrics
    result = execute(scenario)
    assert result.reason == "canary-metrics-incomplete"
    assert result.state is rr.ReleaseState.ROLLED_BACK


def test_rollback_query_failure_preserves_unknown_state():
    scenario = fixtures.build_scenario()
    scenario.provider.metrics.clear()
    scenario.provider.unavailable_queries.add("rollout:support-agent:500:production:rollback")
    result = execute(scenario)
    assert result.state is rr.ReleaseState.ROLLBACK_UNKNOWN
    assert not result.rollback_verified


def test_timeout_after_canary_commit_is_unknown_without_retry():
    scenario = fixtures.build_scenario()
    _, plan, _ = fixtures.approved_release(scenario)
    scenario.provider.timeout_after_commit.add(plan.logical_operation_id)
    result = execute(scenario)
    assert result.state is rr.ReleaseState.OUTCOME_UNKNOWN
    assert scenario.provider.deployment_effects == 1
    assert scenario.provider.query(plan.logical_operation_id).status is rr.ProviderStatus.CANARY


def test_unavailable_pre_dispatch_query_causes_no_effect():
    scenario = fixtures.build_scenario()
    _, plan, _ = fixtures.approved_release(scenario)
    scenario.provider.unavailable_queries.add(plan.logical_operation_id)
    result = execute(scenario)
    assert result.reason == "provider-query-unavailable"
    assert scenario.provider.deployment_effects == 0


def test_same_operation_id_with_different_release_is_denied():
    scenario = fixtures.build_scenario()
    _, plan, _ = fixtures.approved_release(scenario)
    scenario.provider.observations[plan.logical_operation_id] = rr.ProviderObservation(
        plan.logical_operation_id, "sha256:other", rr.ProviderStatus.CANARY,
    )
    assert execute(scenario).reason == "logical-operation-intent-conflict"


def test_current_authorization_is_rechecked_before_approval_consumption():
    scenario = fixtures.build_scenario()
    _, _, approval = fixtures.approved_release(scenario)
    result = execute(scenario, authorizer=rr.CurrentAuthorizer(frozenset()))
    assert result.reason == "current-authorization-denied"
    assert approval.approval_id not in scenario.executor.used_approvals
    assert scenario.provider.deployment_effects == 0


def test_cross_tenant_operator_cannot_use_a_different_tenant_grant():
    scenario = fixtures.build_scenario()
    actor = rr.ReleaseActor("operator:south:2", "south", frozenset({"release-operator"}))
    authorizer = rr.CurrentAuthorizer(frozenset({("south", "production", "write-support-case")}))
    result = execute(scenario, actor=actor, authorizer=authorizer)
    assert result.reason == "current-authorization-denied"
    assert scenario.provider.deployment_effects == 0


def test_operator_and_approver_must_be_separate_people():
    scenario = fixtures.build_scenario()
    _, plan, approval = fixtures.approved_release(scenario)
    same_person = scenario.keyring.sign_approval(
        replace(approval, approved_by=scenario.actor.subject, proof=""), approval.key_id,
    )
    assert execute(scenario, plan=plan, approval=same_person).reason == "invalid-or-consumed-approval"


@pytest.mark.parametrize("mutation", [
    {"plan_digest": "wrong"},
    {"release_digest": "sha256:other"},
    {"tenant": "south"},
    {"expected_release_version": 99},
    {"proof": "00"},
])
def test_approval_is_bound_to_exact_plan_release_tenant_version_and_proof(mutation):
    scenario = fixtures.build_scenario()
    _, plan, approval = fixtures.approved_release(scenario)
    assert execute(scenario, plan=plan, approval=replace(approval, **mutation)).reason == "invalid-or-consumed-approval"


def test_consumed_approval_cannot_authorize_a_second_rollout():
    scenario = fixtures.build_scenario()
    _, plan, approval = fixtures.approved_release(scenario)
    first = scenario.executor.execute(
        scenario.record, plan, approval, scenario.actor, scenario.authorizer,
        scenario.provider, now=120,
    )
    second = scenario.executor.execute(
        scenario.record, plan, approval, scenario.actor, scenario.authorizer,
        scenario.provider, now=120,
    )
    assert first.state is rr.ReleaseState.PROMOTED
    assert second.reason in {"plan-context-mismatch", "invalid-or-consumed-approval"}
    assert scenario.provider.deployment_effects == 1


def test_plan_digest_tampering_is_rejected():
    scenario = fixtures.build_scenario()
    _, plan, approval = fixtures.approved_release(scenario)
    tampered = replace(plan, canary_percent=90)
    assert execute(scenario, plan=tampered, approval=approval).reason == "invalid-plan-digest"


@pytest.mark.parametrize("changes", [
    {"canary_percent": 90},
    {"max_error_rate": 0.50},
    {"min_safety_rate": 0.50},
    {"max_p95_latency_ms": 5_000},
    {"max_cost_per_task": 10.0},
])
def test_signed_plan_cannot_weaken_trusted_rollout_thresholds(changes):
    scenario = fixtures.build_scenario()
    _, plan, approval = fixtures.approved_release(scenario)
    weakened = rr.bind_plan(replace(plan, **changes, plan_digest=""))
    rebound = scenario.keyring.sign_approval(
        replace(approval, plan_digest=weakened.plan_digest, proof=""), approval.key_id,
    )
    assert execute(scenario, plan=weakened, approval=rebound).reason == "plan-context-mismatch"


def test_gate_is_re_evaluated_at_execution_time():
    scenario = fixtures.build_scenario()
    _, plan, approval = fixtures.approved_release(scenario)
    result = execute(scenario, plan=plan, approval=approval, now=401)
    assert result.reason.startswith("release-gate-")
    assert scenario.provider.deployment_effects == 0


def test_lab_reports_denominators_and_zero_severe_escape():
    report = lab.run_lab()["evaluation"]
    assert report["valid_cases"] == 1
    assert report["attack_cases"] == 3
    assert report["failure_cases"] == 2
    assert report["severe_failure_escape_rate"] == 0.0
    assert report["duplicate_deployment_effects"] == 0
