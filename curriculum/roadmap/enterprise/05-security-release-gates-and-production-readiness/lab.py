"""Credential-free executable lab for Enterprise Course 05."""
from __future__ import annotations

from dataclasses import asdict, replace
import json

import release_fixtures as fixtures
import release_readiness as rr


def evaluate_controls() -> rr.EvaluationReport:
    baseline = fixtures.build_scenario()
    ready, plan, approval = fixtures.approved_release(baseline)
    baseline_result = baseline.executor.execute(
        baseline.record, plan, approval, baseline.actor, baseline.authorizer,
        baseline.provider, now=120,
    )

    # Attack 1: one critical adversarial failure must remain outside averages.
    severe = fixtures.build_scenario()
    evidence_id = "evidence:adversarial-eval:500"
    original = severe.store.evidence[evidence_id]
    severe.store.evidence[evidence_id] = replace(
        original, severe_failures=1, result=rr.EvidenceResult.FAIL,
    )
    severe_decision = severe.gate.evaluate(
        release_digest=severe.record.candidate_digest, tenant="north",
        environment="production", policy_version=severe.executor.current_policy_version,
        now=120,
    )

    # Attack 2: presence-only evidence with almost no exercised cases fails.
    shallow = fixtures.build_scenario()
    shallow_id = "evidence:integration-test:500"
    shallow.store.evidence[shallow_id] = replace(
        shallow.store.evidence[shallow_id], checked=100, passed=1,
    )
    shallow_decision = shallow.gate.evaluate(
        release_digest=shallow.record.candidate_digest, tenant="north",
        environment="production", policy_version=shallow.executor.current_policy_version,
        now=120,
    )

    # Attack 3: an exception cannot waive a non-waivable severe outcome.
    severe_exception = fixtures.signed_exception(severe, "severe-failure")
    exception_decision = severe.gate.evaluate(
        release_digest=severe.record.candidate_digest, tenant="north",
        environment="production", policy_version=severe.executor.current_policy_version,
        now=120, exceptions=(severe_exception,),
    )

    # Boundary: an old but still present artifact is stale under policy.
    stale = fixtures.build_scenario()
    stale_decision = stale.gate.evaluate(
        release_digest=stale.record.candidate_digest, tenant="north",
        environment="production", policy_version=stale.executor.current_policy_version,
        now=401,
    )

    # Failure 1: unsafe canary rolls back and verifies the stable digest.
    unsafe = fixtures.build_scenario()
    unsafe.provider.metrics[unsafe.record.candidate_digest] = rr.CanaryMetrics(
        100, 1, 0.01, 0.99, 430, 0.08,
    )
    _, unsafe_plan, unsafe_approval = fixtures.approved_release(unsafe)
    rollback = unsafe.executor.execute(
        unsafe.record, unsafe_plan, unsafe_approval, unsafe.actor,
        unsafe.authorizer, unsafe.provider, now=120,
    )

    # Failure 2: timeout after deployment is UNKNOWN, not permission to retry.
    timeout = fixtures.build_scenario()
    _, timeout_plan, timeout_approval = fixtures.approved_release(timeout)
    timeout.provider.timeout_after_commit.add(timeout_plan.logical_operation_id)
    unknown = timeout.executor.execute(
        timeout.record, timeout_plan, timeout_approval, timeout.actor,
        timeout.authorizer, timeout.provider, now=120,
    )
    effects_before = timeout.provider.deployment_effects
    observation = timeout.provider.query(timeout_plan.logical_operation_id)
    duplicate_effects = timeout.provider.deployment_effects - effects_before

    assert ready.state is rr.GateState.READY
    assert baseline_result.state is rr.ReleaseState.PROMOTED
    assert severe_decision.state is rr.GateState.BLOCKED
    assert shallow_decision.state is rr.GateState.BLOCKED
    assert exception_decision.state is rr.GateState.BLOCKED
    assert stale_decision.state is not rr.GateState.READY
    assert rollback.state is rr.ReleaseState.ROLLED_BACK and rollback.rollback_verified
    assert unknown.state is rr.ReleaseState.OUTCOME_UNKNOWN
    assert observation.status is rr.ProviderStatus.CANARY
    assert duplicate_effects == 0

    return rr.EvaluationReport(
        valid_cases=1,
        attack_cases=3,
        boundary_cases=1,
        failure_cases=2,
        ready_rate=1.0,
        severe_failure_escape_rate=0.0,
        stale_evidence_rejection_rate=1.0,
        rollback_success_rate=1.0,
        duplicate_deployment_effects=duplicate_effects,
        false_block_rate=0.0,
    )


def run_lab() -> dict[str, object]:
    scenario = fixtures.build_scenario()
    decision, plan, approval = fixtures.approved_release(scenario)
    result = scenario.executor.execute(
        scenario.record, plan, approval, scenario.actor, scenario.authorizer,
        scenario.provider, now=120,
    )
    return {
        "gate": asdict(decision),
        "plan_digest": plan.plan_digest,
        "rollout": asdict(result),
        "provider": {
            "deployment_effects": scenario.provider.deployment_effects,
            "rollback_effects": scenario.provider.rollback_effects,
        },
        "evaluation": asdict(evaluate_controls()),
    }


if __name__ == "__main__":
    print(json.dumps(run_lab(), indent=2, default=lambda value: value.value))
