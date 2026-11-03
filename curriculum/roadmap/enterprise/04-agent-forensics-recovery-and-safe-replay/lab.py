"""Credential-free executable lab for Enterprise Course 04."""
from __future__ import annotations

from dataclasses import asdict, replace
import json

import fixtures
import forensics_recovery as fr


def evaluate_controls() -> fr.EvaluationReport:
    # Two valid populations: one replays a missing effect; one skips both
    # effects because the provider already committed them.
    baseline = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(baseline)
    baseline_result = baseline.executor.execute(
        baseline.case, plan, approval, baseline.responder, baseline.provider,
        baseline.authorizer, now=121,
    )

    committed = fixtures.build_scenario()
    audit_intent = committed.checkpoint.effects[1]
    committed.provider.observations[audit_intent.logical_operation_id] = fr.ProviderObservation(
        audit_intent.logical_operation_id, audit_intent.intent_digest,
        fr.EffectStatus.COMMITTED, True, "resource:audit:42",
    )
    committed_plan, committed_approval = fixtures.approved_recovery(committed)
    committed_result = committed.executor.execute(
        committed.case, committed_plan, committed_approval, committed.responder,
        committed.provider, committed.authorizer, now=121,
    )
    valid_successes = sum(
        result.state is fr.RecoveryState.RECOVERED
        for result in (baseline_result, committed_result)
    )

    # Attack 1: modifying admitted evidence is detected before planning.
    tampered = fixtures.build_scenario()
    event_id = "event:effect-result:42"
    tampered.store.events[event_id] = fixtures.altered_event(
        tampered.store.events[event_id], payload_digest=fr.digest("forged-success"),
    )
    tamper_report = tampered.analyzer.analyze(
        case_id=tampered.checkpoint.case_id,
        tenant=tampered.checkpoint.tenant,
        required_event_ids=tampered.checkpoint.expected_event_ids,
        source_high_watermarks=tampered.checkpoint.source_high_watermarks,
    )

    # Attack 2: the same logical ID with different intent is denied.
    conflict = fixtures.build_scenario()
    effect = conflict.checkpoint.effects[0]
    conflict.provider.observations[effect.logical_operation_id] = fr.ProviderObservation(
        effect.logical_operation_id, fr.digest("different-intent"),
        fr.EffectStatus.COMMITTED, True,
    )
    conflict_plan, _ = fixtures.approved_recovery(conflict)
    conflict_denied = conflict_plan.items[0].decision is fr.ReplayDecision.DENIED

    # Attack 3: current authorization is checked before consuming approval.
    unauthorized = fixtures.build_scenario()
    unauthorized_plan, unauthorized_approval = fixtures.approved_recovery(unauthorized)
    unauthorized_result = unauthorized.executor.execute(
        unauthorized.case, unauthorized_plan, unauthorized_approval,
        unauthorized.responder, unauthorized.provider, fr.CurrentAuthorizer(frozenset()), now=121,
    )
    unauthorized_denied = not unauthorized_result.accepted and unauthorized.provider.effect_count == 0

    # Boundary populations retain explicit non-executable states.
    unavailable = fixtures.build_scenario()
    unavailable.provider.unavailable_ids.add(unavailable.checkpoint.effects[1].logical_operation_id)
    unavailable_plan, _ = fixtures.approved_recovery(unavailable)
    unavailable_reconciles = unavailable_plan.items[1].decision is fr.ReplayDecision.RECONCILE_REQUIRED

    manual = fixtures.build_scenario()
    manual_effects = (
        manual.checkpoint.effects[0],
        replace(manual.checkpoint.effects[1], replayable=False),
    )
    manual.checkpoint = manual.keyring.sign_checkpoint(
        replace(manual.checkpoint, effects=manual_effects, signature=""),
        "checkpoint-authority-2026-11",
    )
    manual_plan, _ = fixtures.approved_recovery(manual)
    manual_reviews = manual_plan.items[1].decision is fr.ReplayDecision.REVIEW_REQUIRED

    # Failure 1: timeout after commit remains unknown; a new plan reconciles
    # the original logical operation and does not create a duplicate effect.
    timeout = fixtures.build_scenario()
    audit_id = timeout.checkpoint.effects[1].logical_operation_id
    timeout.provider.timeout_after_commit_ids.add(audit_id)
    timeout_plan, timeout_approval = fixtures.approved_recovery(timeout)
    timeout_result = timeout.executor.execute(
        timeout.case, timeout_plan, timeout_approval, timeout.responder,
        timeout.provider, timeout.authorizer, now=121,
    )
    first_effect_count = timeout.provider.effect_count
    timeout.provider.timeout_after_commit_ids.clear()
    reconciled_plan, reconciled_approval = fixtures.approved_recovery(
        timeout, now=130, approval_id="approval:recovery:42:reconciled",
    )
    reconciled_result = timeout.executor.execute(
        timeout.case, reconciled_plan, reconciled_approval, timeout.responder,
        timeout.provider, timeout.authorizer, now=131,
    )
    duplicate_effect_count = timeout.provider.effect_count - first_effect_count
    unknown_reconciled = (
        timeout_result.state is fr.RecoveryState.RECOVERY_INCOMPLETE
        and reconciled_result.state is fr.RecoveryState.RECOVERED
        and duplicate_effect_count == 0
    )

    # Failure 2: changed policy invalidates the exact prior plan and approval.
    stale_policy = fixtures.build_scenario()
    stale_plan, stale_approval = fixtures.approved_recovery(stale_policy)
    stale_policy.executor.current_policy_version = "recovery-policy-2026-12"
    stale_result = stale_policy.executor.execute(
        stale_policy.case, stale_plan, stale_approval, stale_policy.responder,
        stale_policy.provider, stale_policy.authorizer, now=121,
    )

    unsafe_executions = 0
    attack_controls = (
        bool(tamper_report.tampered_event_ids), conflict_denied, unauthorized_denied,
    )
    boundary_controls = (unavailable_reconciles, manual_reviews)
    failure_controls = (unknown_reconciled, not stale_result.accepted)
    assert all(attack_controls + boundary_controls + failure_controls)
    return fr.EvaluationReport(
        valid_cases=2,
        attack_cases=3,
        boundary_cases=2,
        failure_cases=2,
        chronology_completion_rate=sum((baseline.report.complete, committed.report.complete)) / 2,
        tamper_detection_rate=float(bool(tamper_report.tampered_event_ids)),
        unsafe_replay_rate=unsafe_executions / 3,
        duplicate_effect_count=duplicate_effect_count,
        valid_recovery_success_rate=valid_successes / 2,
        false_block_rate=(2 - valid_successes) / 2,
        unknown_outcomes_reconciled_rate=float(unknown_reconciled),
    )


def run_lab() -> dict[str, object]:
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    result = scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    )
    return {
        "chronology": asdict(scenario.report),
        "plan_decisions": fr.plan_decision_counts(plan.items),
        "recovery": {
            "accepted": result.accepted,
            "reason": result.reason,
            "state": result.state.value,
            "receipts": [asdict(receipt) for receipt in result.receipts],
        },
        "provider_effect_count": scenario.provider.effect_count,
        "ed25519_public_key": scenario.keyring.public_key_hex("runtime-evidence-2026-11"),
        "evaluation": asdict(evaluate_controls()),
    }


if __name__ == "__main__":
    print(json.dumps(run_lab(), indent=2, default=lambda value: value.value))
