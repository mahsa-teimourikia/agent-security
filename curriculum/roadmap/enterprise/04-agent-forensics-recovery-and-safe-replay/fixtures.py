"""Deterministic fixtures shared by the lab, notebook, and focused tests."""
from __future__ import annotations

from dataclasses import dataclass, replace

import forensics_recovery as fr
from cryptography_adapter import Ed25519Keyring, course_keyring


@dataclass
class CourseScenario:
    keyring: Ed25519Keyring
    store: fr.EvidenceStore
    analyzer: fr.ChronologyAnalyzer
    report: fr.ChronologyReport
    checkpoint: fr.CheckpointManifest
    case: fr.RecoveryCase
    provider: fr.SyntheticProvider
    planner: fr.RecoveryPlanner
    executor: fr.RecoveryExecutor
    responder: fr.Responder
    authorizer: fr.CurrentAuthorizer
    approval_authorities: dict[str, fr.TrustedAuthority]


def make_events(keyring: Ed25519Keyring) -> tuple[fr.ForensicEvent, ...]:
    specs = (
        ("event:checkpoint:42", fr.EventKind.CHECKPOINT, 100, "", "", "checkpoint-bytes:42"),
        ("event:policy:42", fr.EventKind.POLICY_DECISION, 101, "", "", "allow-case-recovery"),
        ("event:effect-request:42", fr.EventKind.EFFECT_REQUEST, 102, "effect:case:42:update", "attempt:1", "case-update"),
        ("event:effect-result:42", fr.EventKind.EFFECT_RESULT, 103, "effect:case:42:update", "attempt:1", "timeout-unknown"),
        ("event:containment:42", fr.EventKind.CONTAINMENT, 104, "", "", "containment-verified"),
    )
    events: list[fr.ForensicEvent] = []
    previous = "GENESIS"
    for sequence, (event_id, kind, observed_at, logical_id, attempt_id, payload) in enumerate(specs, 1):
        event = fr.ForensicEvent(
            event_id=event_id,
            case_id="case:north:42",
            tenant="north",
            producer_id="runtime:north",
            source_sequence=sequence,
            previous_source_digest=previous,
            observed_at=observed_at,
            received_at=observed_at + 1,
            kind=kind,
            run_id="run:north:42",
            checkpoint_id="checkpoint:north:42",
            logical_operation_id=logical_id,
            attempt_id=attempt_id,
            payload_digest=fr.digest(payload),
        )
        signed = keyring.sign_event(event, "runtime-evidence-2026-11")
        events.append(signed)
        previous = fr.event_digest(signed)
    return tuple(events)


def build_scenario() -> CourseScenario:
    keyring = course_keyring()
    producer = fr.TrustedProducer(
        "runtime:north", "north", "runtime-evidence-2026-11",
    )
    store = fr.EvidenceStore({producer.producer_id: producer}, keyring)
    events = make_events(keyring)
    for event in events:
        receipt = store.admit(event, now=110)
        assert receipt.status is fr.Admission.ADMITTED

    analyzer = fr.ChronologyAnalyzer(store)
    required = tuple(event.event_id for event in events)
    watermarks = ((producer.producer_id, len(events)),)
    report = analyzer.analyze(
        case_id="case:north:42",
        tenant="north",
        required_event_ids=required,
        source_high_watermarks=watermarks,
    )
    effects = (
        fr.EffectIntent(
            "effect:case:42:update", "case.update", "case:north:42",
            fr.digest({"status": "contained"}), fr.EffectStatus.UNKNOWN,
        ),
        fr.EffectIntent(
            "effect:case:42:audit", "audit.enqueue", "queue:north:audit",
            fr.digest({"case_id": "case:north:42"}), fr.EffectStatus.NOT_DISPATCHED,
        ),
    )
    checkpoint = fr.CheckpointManifest(
        checkpoint_id="checkpoint:north:42",
        case_id="case:north:42",
        tenant="north",
        run_id="run:north:42",
        state_digest=fr.digest({"case": 42, "phase": "contained"}),
        code_version="support-agent@4.2.1",
        captured_policy_version="recovery-policy-2026-10",
        chronology_digest=report.chronology_digest,
        containment_evidence_id="event:containment:42",
        expected_event_ids=required,
        source_high_watermarks=watermarks,
        effects=effects,
    )
    checkpoint = keyring.sign_checkpoint(checkpoint, "checkpoint-authority-2026-11")

    provider = fr.SyntheticProvider({
        effects[0].logical_operation_id: fr.ProviderObservation(
            effects[0].logical_operation_id, effects[0].intent_digest,
            fr.EffectStatus.COMMITTED, True, "resource:case:42",
        )
    })
    authorities = {
        "checkpoint-authority-2026-11": fr.TrustedAuthority(
            "checkpoint-authority-2026-11", "north", "checkpoint",
        ),
        "recovery-approval-2026-11": fr.TrustedAuthority(
            "recovery-approval-2026-11", "north", "recovery-approval",
        ),
    }
    planner = fr.RecoveryPlanner(
        keyring, authorities, frozenset({"support-agent@4.2.1"}), analyzer,
    )
    executor = fr.RecoveryExecutor(keyring, authorities, "recovery-policy-2026-11")
    case = fr.RecoveryCase(
        "case:north:42", "north", fr.RecoveryState.CONTAINED, 7,
        "commander:north:1",
    )
    responder = fr.Responder(
        "recovery:north:2", "north", frozenset({"recovery_approver"}),
    )
    authorizer = fr.CurrentAuthorizer(frozenset({
        ("north", "audit.enqueue", "queue:north:audit"),
    }))
    return CourseScenario(
        keyring, store, analyzer, report, checkpoint, case, provider, planner,
        executor, responder, authorizer, authorities,
    )


def approved_recovery(scenario: CourseScenario, *, now: int = 120,
                      approval_id: str = "approval:recovery:42") -> tuple[fr.RecoveryPlan, fr.RecoveryApproval]:
    plan = scenario.planner.plan(
        scenario.case, scenario.checkpoint, scenario.provider,
        current_policy_version=scenario.executor.current_policy_version, now=now,
    )
    approval = fr.RecoveryApproval(
        approval_id=approval_id,
        case_id=scenario.case.case_id,
        tenant=scenario.case.tenant,
        plan_digest=plan.plan_digest,
        expected_case_version=scenario.case.version,
        policy_version=scenario.executor.current_policy_version,
        approved_by=scenario.responder.subject,
        issued_at=now,
        expires_at=now + 30,
    )
    return plan, scenario.keyring.sign_approval(approval, "recovery-approval-2026-11")


def altered_event(event: fr.ForensicEvent, **changes: object) -> fr.ForensicEvent:
    """Change signed content without resigning, modelling storage tampering."""
    return replace(event, **changes)
