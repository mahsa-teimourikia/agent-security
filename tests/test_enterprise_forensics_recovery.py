"""Invariant tests for Enterprise Course 04 forensics and safe replay."""
from __future__ import annotations

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE_DIR = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/04-agent-forensics-recovery-and-safe-replay"
sys.path.insert(0, str(COURSE_DIR))

import cryptography_adapter as crypto  # noqa: E402
import fixtures  # noqa: E402
import forensics_recovery as fr  # noqa: E402

LAB_SPEC = importlib.util.spec_from_file_location("enterprise_04_recovery_lab", COURSE_DIR / "lab.py")
assert LAB_SPEC and LAB_SPEC.loader
lab = importlib.util.module_from_spec(LAB_SPEC)
sys.modules[LAB_SPEC.name] = lab
LAB_SPEC.loader.exec_module(lab)


def resigned_event(scenario: fixtures.CourseScenario, event: fr.ForensicEvent, **changes: object) -> fr.ForensicEvent:
    unsigned = replace(event, **changes, signature="")
    return scenario.keyring.sign_event(unsigned, unsigned.key_id)


def resigned_checkpoint(scenario: fixtures.CourseScenario, **changes: object) -> fr.CheckpointManifest:
    unsigned = replace(scenario.checkpoint, **changes, signature="")
    return scenario.keyring.sign_checkpoint(unsigned, "checkpoint-authority-2026-11")


def fresh_store(enabled: bool = True) -> tuple[crypto.Ed25519Keyring, fr.EvidenceStore, tuple[fr.ForensicEvent, ...]]:
    keyring = crypto.course_keyring()
    producer = fr.TrustedProducer("runtime:north", "north", "runtime-evidence-2026-11", enabled)
    return keyring, fr.EvidenceStore({producer.producer_id: producer}, keyring), fixtures.make_events(keyring)


def test_canonical_digest_preserves_sequence_order_and_normalizes_sets():
    assert fr.digest(["a", "b"]) != fr.digest(["b", "a"])
    assert fr.digest(frozenset({"a", "b"})) == fr.digest(frozenset({"b", "a"}))


def test_real_ed25519_adapter_signs_and_verifies_payload():
    keyring = crypto.course_keyring()
    payload = {"case": "case:north:42", "sequence": 1}
    signature = keyring.sign("runtime-evidence-2026-11", payload)
    assert keyring.verify("runtime-evidence-2026-11", payload, signature)
    assert not keyring.verify("runtime-evidence-2026-11", {**payload, "sequence": 2}, signature)
    assert not keyring.verify("missing-key", payload, signature)
    assert len(keyring.public_key_hex("runtime-evidence-2026-11")) == 64


def test_admits_a_valid_signed_source_chain():
    _, store, events = fresh_store()
    receipts = [store.admit(event, now=110) for event in events]
    assert all(receipt.status is fr.Admission.ADMITTED for receipt in receipts)
    assert store.source_heads["runtime:north"][0] == 5


def test_identical_delivery_is_idempotent():
    _, store, events = fresh_store()
    assert store.admit(events[0], now=110).status is fr.Admission.ADMITTED
    receipt = store.admit(events[0], now=110)
    assert (receipt.status, receipt.reason, len(store.events)) == (
        fr.Admission.IDEMPOTENT, "duplicate-delivery", 1,
    )


def test_identical_late_redelivery_is_still_idempotent():
    _, store, events = fresh_store()
    store.admit(events[0], now=110)
    receipt = store.admit(events[0], now=1_000)
    assert (receipt.status, receipt.reason) == (fr.Admission.IDEMPOTENT, "duplicate-delivery")


def test_same_event_id_with_changed_content_is_quarantined():
    keyring, store, events = fresh_store()
    store.admit(events[0], now=110)
    changed = keyring.sign_event(
        replace(events[0], payload_digest=fr.digest("different"), signature=""),
        "runtime-evidence-2026-11",
    )
    receipt = store.admit(changed, now=110)
    assert (receipt.status, receipt.reason) == (fr.Admission.QUARANTINED, "event-id-conflict")


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ({"producer_id": "unknown"}, "producer-not-trusted"),
        ({"key_id": "checkpoint-authority-2026-11"}, "producer-key-mismatch"),
        ({"signature": "00"}, "invalid-event-signature"),
    ],
)
def test_untrusted_producer_key_or_signature_is_quarantined(mutation: dict[str, object], reason: str):
    _, store, events = fresh_store()
    receipt = store.admit(replace(events[0], **mutation), now=110)
    assert (receipt.status, receipt.reason) == (fr.Admission.QUARANTINED, reason)


def test_disabled_producer_is_quarantined():
    _, store, events = fresh_store(enabled=False)
    assert store.admit(events[0], now=110).reason == "producer-not-trusted"


def test_producer_tenant_comes_from_registry_not_signed_claim():
    keyring, store, events = fresh_store()
    wrong_tenant = keyring.sign_event(
        replace(events[0], tenant="south", signature=""), "runtime-evidence-2026-11",
    )
    assert store.admit(wrong_tenant, now=110).reason == "producer-tenant-mismatch"


@pytest.mark.parametrize(
    ("changes", "now", "reason"),
    [
        ({"case_id": ""}, 110, "required-evidence-missing"),
        ({"received_at": 111}, 110, "event-from-future"),
        ({"observed_at": 116}, 110, "event-from-future"),
        ({"received_at": 1}, 700, "event-too-old"),
    ],
)
def test_required_fields_and_time_bounds_are_enforced(changes: dict[str, object], now: int, reason: str):
    keyring, store, events = fresh_store()
    event = keyring.sign_event(replace(events[0], **changes, signature=""), "runtime-evidence-2026-11")
    assert store.admit(event, now=now).reason == reason


def test_sequence_gap_is_not_silently_sorted_away():
    keyring, store, events = fresh_store()
    store.admit(events[0], now=110)
    jumped = keyring.sign_event(replace(events[1], source_sequence=3, signature=""), "runtime-evidence-2026-11")
    assert store.admit(jumped, now=110).reason == "source-sequence-gap"


def test_sequence_regression_is_quarantined():
    keyring, store, events = fresh_store()
    store.admit(events[0], now=110)
    store.admit(events[1], now=110)
    replay = keyring.sign_event(
        replace(events[1], event_id="event:late-copy", signature=""), "runtime-evidence-2026-11",
    )
    assert store.admit(replay, now=110).reason == "source-sequence-regression"


def test_broken_source_chain_is_quarantined():
    keyring, store, events = fresh_store()
    store.admit(events[0], now=110)
    broken = keyring.sign_event(
        replace(events[1], previous_source_digest="forged", signature=""), "runtime-evidence-2026-11",
    )
    assert store.admit(broken, now=110).reason == "source-chain-mismatch"


def test_complete_chronology_binds_exact_event_digests():
    scenario = fixtures.build_scenario()
    assert scenario.report.complete
    assert len(scenario.report.ordered_event_ids) == 5
    assert scenario.checkpoint.chronology_digest == scenario.report.chronology_digest


def test_chronology_reports_missing_required_event():
    scenario = fixtures.build_scenario()
    report = scenario.analyzer.analyze(
        case_id=scenario.report.case_id,
        tenant=scenario.report.tenant,
        required_event_ids=scenario.checkpoint.expected_event_ids + ("event:required:missing",),
        source_high_watermarks=scenario.checkpoint.source_high_watermarks,
    )
    assert not report.complete and report.missing_required_event_ids == ("event:required:missing",)


def test_chronology_reports_expected_high_watermark_gap():
    scenario = fixtures.build_scenario()
    report = scenario.analyzer.analyze(
        case_id=scenario.report.case_id,
        tenant=scenario.report.tenant,
        required_event_ids=scenario.checkpoint.expected_event_ids,
        source_high_watermarks=(("runtime:north", 6),),
    )
    assert not report.complete and report.sequence_gaps == ("runtime:north:6",)


def test_chronology_reverification_detects_storage_tampering():
    scenario = fixtures.build_scenario()
    event_id = "event:effect-result:42"
    scenario.store.events[event_id] = fixtures.altered_event(
        scenario.store.events[event_id], payload_digest=fr.digest("forged-success"),
    )
    report = scenario.analyzer.analyze(
        case_id=scenario.report.case_id,
        tenant=scenario.report.tenant,
        required_event_ids=scenario.checkpoint.expected_event_ids,
        source_high_watermarks=scenario.checkpoint.source_high_watermarks,
    )
    assert event_id in report.tampered_event_ids and not report.complete


def test_planner_skips_committed_effect_and_allows_authoritative_absence():
    scenario = fixtures.build_scenario()
    plan, _ = fixtures.approved_recovery(scenario)
    assert [item.decision for item in plan.items] == [
        fr.ReplayDecision.SKIP_COMMITTED, fr.ReplayDecision.REPLAY_ALLOWED,
    ]


@pytest.mark.parametrize(
    ("change", "error"),
    [
        ({"key_id": "missing"}, "checkpoint-authority-not-trusted"),
        ({"signature": "00"}, "invalid-checkpoint-signature"),
        ({"chronology_digest": "wrong"}, "checkpoint-chronology-mismatch"),
        ({"expected_event_ids": (
            "event:checkpoint:42", "event:policy:42", "event:effect-request:42",
            "event:effect-result:42",
        )}, "checkpoint-chronology-mismatch"),
        ({"containment_evidence_id": "event:missing"}, "verified-containment-evidence-required"),
        ({"code_version": "support-agent@unreviewed"}, "checkpoint-code-version-not-approved"),
    ],
)
def test_checkpoint_trust_bindings_block_planning(change: dict[str, object], error: str):
    scenario = fixtures.build_scenario()
    checkpoint = replace(scenario.checkpoint, **change)
    if "signature" not in change and "key_id" not in change:
        checkpoint = resigned_checkpoint(scenario, **change)
    with pytest.raises((PermissionError, RuntimeError), match=error):
        scenario.planner.plan(
            scenario.case, checkpoint, scenario.provider,
            current_policy_version=scenario.executor.current_policy_version, now=120,
        )


def test_compromised_checkpoint_is_never_replayed():
    scenario = fixtures.build_scenario()
    scenario.planner.compromised_checkpoints = frozenset({scenario.checkpoint.checkpoint_id})
    with pytest.raises(PermissionError, match="checkpoint-compromised"):
        fixtures.approved_recovery(scenario)


def test_incomplete_chronology_blocks_planning():
    scenario = fixtures.build_scenario()
    del scenario.store.events["event:containment:42"]
    with pytest.raises(RuntimeError, match="complete-chronology-required"):
        scenario.planner.plan(
            scenario.case, scenario.checkpoint, scenario.provider,
            current_policy_version=scenario.executor.current_policy_version, now=120,
        )


@pytest.mark.parametrize("changes", [
    {"effects": ()},
    {"captured_policy_version": ""},
    {"expected_event_ids": ()},
    {"source_high_watermarks": ()},
])
def test_incomplete_checkpoint_manifest_is_rejected(changes: dict[str, object]):
    scenario = fixtures.build_scenario()
    checkpoint = resigned_checkpoint(scenario, **changes)
    with pytest.raises(ValueError, match="checkpoint-manifest-incomplete"):
        scenario.planner.plan(
            scenario.case, checkpoint, scenario.provider,
            current_policy_version=scenario.executor.current_policy_version, now=120,
        )


def test_recovered_case_cannot_be_replanned():
    scenario = fixtures.build_scenario()
    scenario.case.state = fr.RecoveryState.RECOVERED
    with pytest.raises(RuntimeError, match="case-not-ready-for-recovery-planning"):
        fixtures.approved_recovery(scenario)


def test_a_planned_case_can_supersede_an_expired_or_stale_plan():
    scenario = fixtures.build_scenario()
    first_plan, first_approval = fixtures.approved_recovery(scenario)
    second_plan, _ = fixtures.approved_recovery(
        scenario, now=121, approval_id="approval:superseding-plan",
    )
    assert second_plan.expected_case_version > first_plan.expected_case_version
    result = scenario.executor.execute(
        scenario.case, first_plan, first_approval, scenario.responder,
        scenario.provider, scenario.authorizer, now=122,
    )
    assert result.reason == "case-version-conflict"


def test_provider_unavailability_requires_reconciliation():
    scenario = fixtures.build_scenario()
    scenario.provider.unavailable_ids.add(scenario.checkpoint.effects[1].logical_operation_id)
    plan, _ = fixtures.approved_recovery(scenario)
    assert plan.items[1].decision is fr.ReplayDecision.RECONCILE_REQUIRED


def test_same_id_with_different_intent_is_denied():
    scenario = fixtures.build_scenario()
    effect = scenario.checkpoint.effects[0]
    scenario.provider.observations[effect.logical_operation_id] = fr.ProviderObservation(
        effect.logical_operation_id, "wrong-intent", fr.EffectStatus.COMMITTED, True,
    )
    plan, _ = fixtures.approved_recovery(scenario)
    assert (plan.items[0].decision, plan.items[0].reason) == (
        fr.ReplayDecision.DENIED, "idempotency-intent-conflict",
    )


def test_non_replayable_operation_requires_review():
    scenario = fixtures.build_scenario()
    effects = (scenario.checkpoint.effects[0], replace(scenario.checkpoint.effects[1], replayable=False))
    scenario.checkpoint = resigned_checkpoint(scenario, effects=effects)
    plan, _ = fixtures.approved_recovery(scenario)
    assert plan.items[1].decision is fr.ReplayDecision.REVIEW_REQUIRED


def test_final_provider_failure_can_be_replayed():
    scenario = fixtures.build_scenario()
    effect = scenario.checkpoint.effects[1]
    scenario.provider.observations[effect.logical_operation_id] = fr.ProviderObservation(
        effect.logical_operation_id, effect.intent_digest, fr.EffectStatus.FAILED, True,
    )
    plan, _ = fixtures.approved_recovery(scenario)
    assert plan.items[1].decision is fr.ReplayDecision.REPLAY_ALLOWED


def test_committed_history_with_provider_absence_is_denied():
    scenario = fixtures.build_scenario()
    effects = (scenario.checkpoint.effects[0], replace(scenario.checkpoint.effects[1], prior_status=fr.EffectStatus.COMMITTED))
    scenario.checkpoint = resigned_checkpoint(scenario, effects=effects)
    plan, _ = fixtures.approved_recovery(scenario)
    assert plan.items[1].reason == "history-provider-conflict"


def test_valid_recovery_skips_one_effect_and_executes_one():
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    result = scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    )
    assert result.accepted and result.state is fr.RecoveryState.RECOVERED
    assert scenario.provider.effect_count == 1
    assert all(receipt.verified for receipt in result.receipts)


@pytest.mark.parametrize(
    ("responder_change", "reason"),
    [
        ({"authenticated": False}, "recovery-approver-required"),
        ({"roles": frozenset()}, "recovery-approver-required"),
        ({"subject": "other:north"}, "approver-binding-mismatch"),
        ({"subject": "commander:north:1"}, "approver-binding-mismatch"),
        ({"tenant": "south"}, "tenant-mismatch"),
    ],
)
def test_responder_identity_role_and_tenant_are_bound(responder_change: dict[str, object], reason: str):
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    responder = replace(scenario.responder, **responder_change)
    result = scenario.executor.execute(
        scenario.case, plan, approval, responder, scenario.provider,
        scenario.authorizer, now=121,
    )
    assert not result.accepted and result.reason == reason


def test_incident_commander_cannot_approve_recovery_even_with_role():
    scenario = fixtures.build_scenario()
    scenario.responder = fr.Responder(
        scenario.case.incident_commander, "north", frozenset({"recovery_approver"}),
    )
    plan = scenario.planner.plan(
        scenario.case, scenario.checkpoint, scenario.provider,
        current_policy_version=scenario.executor.current_policy_version, now=120,
    )
    approval = fr.RecoveryApproval(
        "approval:dual-role", scenario.case.case_id, "north", plan.plan_digest,
        scenario.case.version, scenario.executor.current_policy_version,
        scenario.responder.subject, 120, 150,
    )
    approval = scenario.keyring.sign_approval(approval, "recovery-approval-2026-11")
    result = scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    )
    assert result.reason == "recovery-separation-required"


def test_invalid_approval_signature_is_rejected():
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    result = scenario.executor.execute(
        scenario.case, plan, replace(approval, signature="00"), scenario.responder,
        scenario.provider, scenario.authorizer, now=121,
    )
    assert result.reason == "invalid-approval-signature"


def test_approval_is_single_use():
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    first = scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    )
    second = scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=122,
    )
    assert first.accepted and second.reason == "approval-already-used"


def test_approval_binds_exact_plan_and_case_version():
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    changed_plan = replace(plan, expires_at=plan.expires_at + 1)
    assert scenario.executor.execute(
        scenario.case, changed_plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    ).reason == "plan-binding-mismatch"

    versioned = fixtures.build_scenario()
    versioned_plan, versioned_approval = fixtures.approved_recovery(versioned)
    versioned.case.version += 1
    assert versioned.executor.execute(
        versioned.case, versioned_plan, versioned_approval, versioned.responder,
        versioned.provider, versioned.authorizer, now=121,
    ).reason == "case-version-conflict"


def test_execution_requires_planned_state_and_approval_after_plan_issue():
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    scenario.case.state = fr.RecoveryState.CONTAINED
    assert scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    ).reason == "case-not-planned"

    early = fixtures.build_scenario()
    early_plan, early_approval = fixtures.approved_recovery(early)
    early_approval = early.keyring.sign_approval(
        replace(early_approval, issued_at=early_plan.issued_at - 1, signature=""),
        "recovery-approval-2026-11",
    )
    assert early.executor.execute(
        early.case, early_plan, early_approval, early.responder, early.provider,
        early.authorizer, now=121,
    ).reason == "recovery-authority-not-current"


def test_policy_change_and_expiry_invalidate_recovery_authority():
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    scenario.executor.current_policy_version = "recovery-policy-2026-12"
    assert scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    ).reason == "recovery-policy-changed"

    expired = fixtures.build_scenario()
    expired_plan, expired_approval = fixtures.approved_recovery(expired)
    assert expired.executor.execute(
        expired.case, expired_plan, expired_approval, expired.responder,
        expired.provider, expired.authorizer, now=151,
    ).reason == "recovery-authority-not-current"


def test_unresolved_items_and_current_authorization_block_before_consumption():
    unresolved = fixtures.build_scenario()
    unresolved.provider.unavailable_ids.add(unresolved.checkpoint.effects[1].logical_operation_id)
    plan, approval = fixtures.approved_recovery(unresolved)
    result = unresolved.executor.execute(
        unresolved.case, plan, approval, unresolved.responder, unresolved.provider,
        unresolved.authorizer, now=121,
    )
    assert result.reason == "unresolved-replay-items"
    assert approval.approval_id not in unresolved.executor.used_approvals

    unauthorized = fixtures.build_scenario()
    auth_plan, auth_approval = fixtures.approved_recovery(unauthorized)
    result = unauthorized.executor.execute(
        unauthorized.case, auth_plan, auth_approval, unauthorized.responder,
        unauthorized.provider, fr.CurrentAuthorizer(frozenset()), now=121,
    )
    assert result.reason == "current-authorization-denied"
    assert auth_approval.approval_id not in unauthorized.executor.used_approvals


def test_timeout_after_commit_stays_unknown_and_does_not_duplicate_on_replan():
    scenario = fixtures.build_scenario()
    logical_id = scenario.checkpoint.effects[1].logical_operation_id
    scenario.provider.timeout_after_commit_ids.add(logical_id)
    plan, approval = fixtures.approved_recovery(scenario)
    first = scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    )
    assert first.state is fr.RecoveryState.RECOVERY_INCOMPLETE
    assert scenario.provider.effect_count == 1
    scenario.provider.timeout_after_commit_ids.clear()
    second_plan, second_approval = fixtures.approved_recovery(
        scenario, now=130, approval_id="approval:reconciled",
    )
    second = scenario.executor.execute(
        scenario.case, second_plan, second_approval, scenario.responder,
        scenario.provider, scenario.authorizer, now=131,
    )
    assert second.state is fr.RecoveryState.RECOVERED
    assert scenario.provider.effect_count == 1


def test_commit_winning_race_is_verified_without_duplicate_dispatch():
    scenario = fixtures.build_scenario()
    plan, approval = fixtures.approved_recovery(scenario)
    intent = scenario.checkpoint.effects[1]
    scenario.provider.observations[intent.logical_operation_id] = fr.ProviderObservation(
        intent.logical_operation_id, intent.intent_digest, fr.EffectStatus.COMMITTED, True,
    )
    result = scenario.executor.execute(
        scenario.case, plan, approval, scenario.responder, scenario.provider,
        scenario.authorizer, now=121,
    )
    assert result.state is fr.RecoveryState.RECOVERED
    assert result.receipts[1].reason == "commit-won-race"
    assert scenario.provider.effect_count == 0


def test_provider_idempotency_reuses_original_logical_operation_id():
    scenario = fixtures.build_scenario()
    intent = scenario.checkpoint.effects[1]
    first = scenario.provider.execute(intent)
    second = scenario.provider.execute(intent)
    assert first == second and scenario.provider.effect_count == 1
    with pytest.raises(ValueError, match="idempotency-intent-conflict"):
        scenario.provider.execute(replace(intent, argument_digest="different"))


def test_evaluation_metrics_have_explicit_populations_and_correct_directions():
    report = lab.evaluate_controls()
    assert (report.valid_cases, report.attack_cases, report.boundary_cases, report.failure_cases) == (2, 3, 2, 2)
    assert report.chronology_completion_rate == 1.0
    assert report.tamper_detection_rate == 1.0
    assert report.unsafe_replay_rate == 0.0
    assert report.duplicate_effect_count == 0
    assert report.valid_recovery_success_rate == 1.0
    assert report.false_block_rate == 0.0
    assert report.unknown_outcomes_reconciled_rate == 1.0
