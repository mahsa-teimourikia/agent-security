"""Focused trust, lifecycle, concurrency, replay, and telemetry tests for Intermediate 03."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib
from pathlib import Path
import sys
from threading import Lock

import pytest


COURSE = Path(__file__).parent.parent / "curriculum" / "intermediate" / "03-incident-recovery"
sys.path.insert(0, str(COURSE.resolve()))
lab = importlib.import_module("03_incident_recovery")
otel = importlib.import_module("03_incident_recovery_otel")
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)


def test_detection_requires_trusted_scoped_evidence() -> None:
    run, _, _, _, signal, _, _, _ = lab.build_scenario(now=NOW)
    untrusted = replace(signal, detector_id="model-output")
    result = run.detect(untrusted, now=NOW)
    assert not result.allowed and result.reason == "untrusted-detector"
    assert run.phase is lab.Phase.ACTIVE

    run, _, _, _, signal, _, _, _ = lab.build_scenario(now=NOW)
    cross_tenant = replace(signal, tenant="south")
    result = run.detect(cross_tenant, now=NOW)
    assert not result.allowed and result.reason == "signal-scope"

    run, _, _, _, signal, _, _, _ = lab.build_scenario(now=NOW)
    no_evidence = replace(signal, evidence_ids=())
    result = run.detect(no_evidence, now=NOW)
    assert not result.allowed and result.reason == "missing-evidence"


def test_containment_requires_authorized_responder_and_complete_revocation() -> None:
    run, responder, _, _, signal, receipt, _, _ = lab.build_scenario(now=NOW)
    assert run.detect(signal, now=NOW)
    outsider = lab.ActorContext("operator:mallory", "north", frozenset({"viewer"}))
    denied = run.contain(receipt, responder=outsider, now=NOW)
    assert not denied.allowed and denied.reason == "responder-authorization"
    assert run.phase is lab.Phase.DETECTED

    partial = replace(
        receipt,
        confirmed=frozenset({"ticket:write"}),
        failed=frozenset({"network:external"}),
    )
    denied = run.contain(partial, responder=responder, now=NOW)
    assert not denied.allowed and denied.reason == "revocation-incomplete"
    assert run.phase is lab.Phase.DETECTED

    stale = replace(receipt, observed_at=NOW - timedelta(seconds=1))
    denied = run.contain(stale, responder=responder, now=NOW)
    assert not denied.allowed and denied.reason == "revocation-stale"

    allowed = run.contain(receipt, responder=responder, now=NOW)
    assert allowed.allowed and run.phase is lab.Phase.CONTAINED


def test_recovery_plan_binds_checkpoint_scope_and_narrow_capability() -> None:
    run, responder, planner, _, signal, receipt, checkpoint, plan = lab.build_scenario(now=NOW)
    assert run.detect(signal, now=NOW)
    assert run.contain(receipt, responder=responder, now=NOW)

    tampered = replace(checkpoint, state_digest=lab.checkpoint_digest({"version": 999}))
    denied = run.propose_recovery(plan, tampered, planner=planner, now=NOW)
    assert not denied.allowed and denied.reason == "checkpoint-integrity"

    widened = replace(plan, restore_capabilities=frozenset({"ticket:write", "admin"}))
    denied = run.propose_recovery(widened, checkpoint, planner=planner, now=NOW)
    assert not denied.allowed and denied.reason == "capability-restore"

    stale_checkpoint = replace(checkpoint, policy_version="policy-v3")
    stale_plan = replace(plan, policy_version="policy-v3")
    denied = run.propose_recovery(stale_plan, stale_checkpoint, planner=planner, now=NOW)
    assert not denied.allowed and denied.reason == "policy-stale"


def test_approval_is_independent_bound_current_expiring_and_single_use() -> None:
    run, responder, planner, approver, signal, receipt, checkpoint, plan = lab.build_scenario(now=NOW)
    assert run.detect(signal, now=NOW)
    assert run.contain(receipt, responder=responder, now=NOW)
    assert run.propose_recovery(plan, checkpoint, planner=planner, now=NOW)

    self_approver = lab.ActorContext(plan.requested_by, "north", frozenset({"recovery-approver"}))
    self_approval = lab.issue_approval(plan, self_approver, approval_id="approval-self", now=NOW)
    denied = run.authorize_recovery(
        self_approval,
        checkpoint,
        now=NOW,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
    )
    assert not denied.allowed and denied.reason == "approval-independence"

    altered = replace(plan, target="ticket:T-8")
    altered_approval = lab.issue_approval(altered, approver, approval_id="approval-altered", now=NOW)
    denied = run.authorize_recovery(
        altered_approval,
        checkpoint,
        now=NOW,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
    )
    assert not denied.allowed and denied.reason == "approval-binding"

    expired = lab.issue_approval(plan, approver, approval_id="approval-expired", now=NOW, ttl=timedelta(0))
    denied = run.authorize_recovery(
        expired,
        checkpoint,
        now=NOW,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
    )
    assert not denied.allowed and denied.reason == "approval-time"

    current_mismatch = run.authorize_recovery(
        lab.issue_approval(plan, approver, approval_id="approval-stale-policy", now=NOW),
        checkpoint,
        now=NOW,
        current_policy_version="policy-v5",
        current_credential_version=run.credential_version,
    )
    assert not current_mismatch.allowed and current_mismatch.reason == "policy-stale"

    valid = lab.issue_approval(plan, approver, approval_id="approval-valid", now=NOW)
    assert run.authorize_recovery(
        valid,
        checkpoint,
        now=NOW,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
    )
    replay = run.authorize_recovery(
        valid,
        checkpoint,
        now=NOW,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
    )
    assert not replay.allowed and replay.reason == "approval-replay"
    assert "network:external" in run.revoked_capabilities
    assert "ticket:write" not in run.revoked_capabilities

    unauthenticated = lab.ActorContext(
        "operator:ghost",
        "north",
        frozenset({"recovery-approver"}),
        authenticated=False,
    )
    with pytest.raises(ValueError):
        lab.issue_approval(plan, unauthenticated, approval_id="approval-ghost", now=NOW)


def test_unknown_effect_requires_reconciliation_before_retry() -> None:
    run, responder, plan = lab.recover_scenario(now=NOW)
    first = run.execute_effect(
        attempt_id="attempt-1",
        capability="ticket:write",
        now=NOW,
        provider=lambda _: lab.ProviderResult(lab.EffectState.UNKNOWN),
    )
    assert first.state is lab.EffectState.UNKNOWN

    called = False

    def provider(_):
        nonlocal called
        called = True
        return lab.ProviderResult(lab.EffectState.CONFIRMED, "duplicate")

    retry = run.execute_effect(attempt_id="attempt-2", capability="ticket:write", now=NOW, provider=provider)
    assert retry.reason == "reconcile-required" and not called
    assert run.reconcile_effect(
        plan.operation_id,
        lab.ProviderResult(lab.EffectState.CONFIRMED, "provider:T-7"),
        responder=responder,
        now=NOW,
    )
    after = run.execute_effect(attempt_id="attempt-3", capability="ticket:write", now=NOW, provider=provider)
    assert after.reason == "duplicate-confirmed" and not called


def test_provider_confirmation_requires_a_durable_reference() -> None:
    run, responder, plan = lab.recover_scenario(now=NOW)
    missing_reference = run.execute_effect(
        attempt_id="attempt-no-reference",
        capability="ticket:write",
        now=NOW,
        provider=lambda _: lab.ProviderResult(lab.EffectState.CONFIRMED),
    )
    assert missing_reference.state is lab.EffectState.UNKNOWN
    assert missing_reference.reason == "outcome-unknown"
    denied = run.reconcile_effect(
        plan.operation_id,
        lab.ProviderResult(lab.EffectState.CONFIRMED),
        responder=responder,
        now=NOW,
    )
    assert not denied.allowed and denied.reason == "reconciliation-result"

    other_run, _, _ = lab.recover_scenario(now=NOW)
    oversized_reference = other_run.execute_effect(
        attempt_id="attempt-oversized-reference",
        capability="ticket:write",
        now=NOW,
        provider=lambda _: lab.ProviderResult(lab.EffectState.CONFIRMED, "x" * 129),
    )
    assert oversized_reference.state is lab.EffectState.UNKNOWN
    assert oversized_reference.provider_reference is None


def test_effect_reservation_is_atomic_under_concurrency() -> None:
    run, _, _ = lab.recover_scenario(now=NOW)
    guard = Lock()
    calls = 0

    def provider(_):
        nonlocal calls
        with guard:
            calls += 1
        return lab.ProviderResult(lab.EffectState.CONFIRMED, "provider:T-7")

    def invoke(index: int):
        return run.execute_effect(
            attempt_id=f"attempt-{index}",
            capability="ticket:write",
            now=NOW,
            provider=provider,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(invoke, range(8)))

    assert calls == 1
    assert sum(result.reason == "provider-confirmed" for result in results) == 1
    assert sum(result.reason in {"operation-in-progress", "duplicate-confirmed"} for result in results) == 7


def test_event_chain_detects_mutation_and_records_no_sensitive_payloads() -> None:
    run = lab.demo()
    assert run.verify_event_chain()
    original = run.events[0]
    run.events[0] = replace(original, reason="changed")
    assert not run.verify_event_chain()
    rendered = repr(run.events)
    assert "unexpected external destination" not in rendered
    assert "credential-v2" not in rendered


def test_evaluation_metrics_have_explicit_expected_outcomes() -> None:
    report = lab.evaluate_incident_controls()
    assert report.valid_recovery_rate == 1.0
    assert report.attack_block_rate == 1.0
    assert report.containment_failure_count == 1
    assert report.forbidden_effect_count == 0
    assert report.duplicate_effect_count == 0
    assert report.trace_completeness_rate == 1.0


def test_opentelemetry_companion_exports_bounded_decision_spans() -> None:
    run, spans = otel.demo()
    assert run.verify_event_chain()
    assert {span.name for span in spans} == {
        "incident.lifecycle",
        "incident.detect",
        "incident.contain",
        "incident.recovery.propose",
        "incident.recovery.authorize",
        "incident.effect",
    }
    rendered = repr([(span.name, dict(span.attributes)) for span in spans])
    assert "credential-v2" not in rendered
    assert "trace-7" not in rendered
    assert "prompt" not in rendered.lower()
