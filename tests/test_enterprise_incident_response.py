"""Security and pedagogy tests for Enterprise 03 incident response."""
from dataclasses import replace
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/03-agent-incident-detection-and-containment"
sys.path.insert(0, str(COURSE))

import incident_response as ir  # noqa: E402
import otel_adapter  # noqa: E402


def admitted_evidence():
    producer, store, detector, graph, manager = ir.build_system()
    signal = ir.signed_signal(producer)
    receipt = store.admit(signal, received_at=101)
    return producer, store, detector, graph, manager, signal, receipt


def test_authenticated_current_signal_is_admitted():
    _, store, _, _, _, _, receipt = admitted_evidence()
    assert receipt.status is ir.Admission.ADMITTED
    assert store.evidence[receipt.evidence_id].source_digest


def test_duplicate_delivery_is_idempotent_and_reuses_evidence():
    _, store, _, _, _, signal, first = admitted_evidence()
    second = store.admit(signal, received_at=102)
    assert second.status is ir.Admission.IDEMPOTENT
    assert second.evidence_id == first.evidence_id
    assert len(store.evidence) == 1


def test_same_event_id_with_different_content_is_denied():
    producer, store, _, _, _, signal, _ = admitted_evidence()
    conflict = ir.SignalSigner.sign(replace(signal, destination="different.evil", signature=""), producer)
    assert store.admit(conflict, received_at=102).reason == "event-id-conflict"


def test_tampered_signed_signal_is_denied():
    _, store, _, _, _, signal, _ = admitted_evidence()
    tampered = replace(ir.signed_signal(next(iter(store.producers.values())), event_id="event:tamper"),
                       destination="changed.evil")
    assert store.admit(tampered, received_at=101).reason == "invalid-signal-signature"


def test_unknown_or_disabled_producer_is_denied():
    producer, store, _, _, _, _, _ = admitted_evidence()
    unknown = replace(ir.signed_signal(producer, event_id="event:unknown"), producer_id="unknown")
    assert store.admit(unknown, received_at=101).reason == "producer-not-trusted"
    store.producers[producer.producer_id] = replace(producer, enabled=False)
    disabled = ir.signed_signal(producer, event_id="event:disabled")
    assert store.admit(disabled, received_at=101).reason == "producer-not-trusted"


def test_producer_cannot_cross_tenants():
    producer, store, _, _, _, _, _ = admitted_evidence()
    cross_tenant = ir.signed_signal(producer, event_id="event:south", tenant="south")
    assert store.admit(cross_tenant, received_at=101).reason == "producer-tenant-mismatch"


def test_required_evidence_fields_cannot_be_empty():
    producer, store, _, _, _, _, _ = admitted_evidence()
    incomplete = ir.signed_signal(producer, event_id="event:empty")
    incomplete = ir.SignalSigner.sign(replace(incomplete, action_id="", signature=""), producer)
    assert store.admit(incomplete, received_at=101).reason == "required-evidence-missing"


@pytest.mark.parametrize(
    ("occurred_at", "received_at", "reason"),
    [(107, 101, "signal-from-future"), (-201, 101, "signal-too-old")],
)
def test_signal_freshness_boundaries(occurred_at, received_at, reason):
    producer, store, _, _, _, _, _ = admitted_evidence()
    signal = ir.signed_signal(producer, event_id=f"event:{reason}", occurred_at=occurred_at)
    assert store.admit(signal, received_at=received_at).reason == reason


def test_detector_requires_committed_unapproved_destination():
    producer, store, detector, _, _, _, _ = admitted_evidence()
    for index, (destination, outcome, kind) in enumerate([
        ("support.internal", "committed", ir.SignalKind.EFFECT_RESULT),
        ("collector.evil", "denied", ir.SignalKind.EFFECT_RESULT),
        ("collector.evil", "committed", ir.SignalKind.EFFECT_ATTEMPT),
    ]):
        signal = ir.signed_signal(producer, event_id=f"event:benign:{index}",
                                  destination=destination, outcome=outcome, kind=kind)
        receipt = store.admit(signal, received_at=101)
        assert detector.detect(store.evidence[receipt.evidence_id]) is None


def test_detector_binds_rule_version_and_evidence():
    _, store, detector, _, _, _, receipt = admitted_evidence()
    alert = detector.detect(store.evidence[receipt.evidence_id])
    assert alert.rule_version == "2026-11-01"
    assert alert.evidence_ids == (receipt.evidence_id,)


def test_duplicate_alerts_open_one_incident():
    _, store, detector, graph, manager, _, receipt = admitted_evidence()
    alert = detector.detect(store.evidence[receipt.evidence_id])
    first = manager.promote(alert, graph.scope(alert))
    second = manager.promote(alert, graph.scope(alert))
    assert first is second
    assert len(manager.incidents) == 1


def test_incident_promotion_requires_admitted_bound_evidence_and_accepted_rule():
    _, store, detector, graph, manager, _, receipt = admitted_evidence()
    alert = detector.detect(store.evidence[receipt.evidence_id])
    with pytest.raises(PermissionError, match="admitted-evidence-required"):
        manager.promote(replace(alert, evidence_ids=("evidence:invented",)), graph.scope(alert))
    with pytest.raises(PermissionError, match="detection-rule-not-accepted"):
        manager.promote(replace(alert, rule_version="unreviewed"), graph.scope(alert))
    with pytest.raises(PermissionError, match="alert-not-reproducible"):
        manager.promote(replace(alert, severity="low"), graph.scope(alert))
    with pytest.raises(PermissionError, match="alert-scope-tenant-mismatch"):
        manager.promote(alert, replace(graph.scope(alert), tenant="south"))


def test_model_summary_does_not_resolve_or_approve_incident():
    incident, _, _, _, _ = ir.open_incident()
    assert "resolving immediately" in incident.model_summary
    assert incident.state is ir.IncidentState.TRIAGED
    assert not incident.action_receipts


def test_missing_asset_mapping_marks_scope_incomplete():
    _, store, detector, _, _, _, receipt = admitted_evidence()
    alert = detector.detect(store.evidence[receipt.evidence_id])
    scope = ir.AssetGraph({}).scope(alert)
    assert not scope.complete
    assert not scope.credential_ids and not scope.queue_ids


def test_valid_plan_executes_exact_action_set_and_verifies_postconditions():
    incident, _, _, service, responder = ir.open_incident()
    connector = ir.SyntheticConnector()
    result = service.execute(incident, ir.approved_plan(incident, service, responder),
                             responder, connector, now=111)
    assert result.reason == "containment-verified"
    assert incident.state is ir.IncidentState.CONTAINED
    assert {receipt.action for receipt in result.receipts} == set(ir.Action)
    assert all(receipt.verified for receipt in result.receipts)


def test_plan_replay_is_denied_without_duplicate_connector_calls():
    incident, _, _, service, responder = ir.open_incident()
    connector = ir.SyntheticConnector()
    plan = ir.approved_plan(incident, service, responder)
    service.execute(incident, plan, responder, connector, now=111)
    call_count = len(connector.calls)
    replay = service.execute(incident, plan, responder, connector, now=112)
    assert replay.reason == "plan-already-used"
    assert len(connector.calls) == call_count


def test_connector_operation_ids_are_idempotent():
    connector = ir.SyntheticConnector()
    first = connector.execute("operation:1", ir.Action.DISABLE_AGENT, "support-7", now=1)
    second = connector.execute("operation:1", ir.Action.DISABLE_AGENT, "support-7", now=99)
    assert first == second
    assert len(connector.calls) == 1


@pytest.mark.parametrize(
    ("responder_change", "expected"),
    [
        ({"authenticated": False}, "responder-not-authenticated"),
        ({"roles": frozenset({"viewer"})}, "incident-commander-required"),
        ({"subject": "other:north"}, "approver-binding-mismatch"),
        ({"tenant": "south"}, "tenant-mismatch"),
    ],
)
def test_responder_identity_and_role_are_enforced(responder_change, expected):
    incident, _, _, service, responder = ir.open_incident()
    plan = ir.approved_plan(incident, service, responder)
    altered = replace(responder, **responder_change)
    result = service.execute(incident, plan, altered, ir.SyntheticConnector(), now=111)
    assert result.reason == expected


def test_plan_tampering_is_denied():
    incident, _, _, service, responder = ir.open_incident()
    plan = replace(ir.approved_plan(incident, service, responder), expires_at=999)
    assert service.execute(incident, plan, responder, ir.SyntheticConnector(), now=111).reason == "invalid-plan-signature"


@pytest.mark.parametrize(
    ("plan_change", "expected"),
    [
        ({"incident_id": "incident:other"}, "incident-binding-mismatch"),
        ({"expected_incident_version": 99}, "incident-version-conflict"),
        ({"scope_digest": "wrong"}, "scope-changed"),
        ({"policy_version": "old"}, "response-policy-changed"),
        ({"actions": (ir.Action.DISABLE_AGENT,)}, "required-action-set-mismatch"),
    ],
)
def test_signed_plan_bindings_are_enforced(plan_change, expected):
    incident, _, _, service, responder = ir.open_incident()
    unsigned = replace(ir.approved_plan(incident, service, responder), **plan_change, signature="")
    plan = service.signer.sign(unsigned)
    result = service.execute(incident, plan, responder, ir.SyntheticConnector(), now=111)
    assert result.reason == expected


def test_plan_must_be_current():
    incident, _, _, service, responder = ir.open_incident()
    plan = ir.approved_plan(incident, service, responder, now=110)
    assert service.execute(incident, plan, responder, ir.SyntheticConnector(), now=140).reason == "plan-not-current"


def test_incomplete_scope_cannot_be_contained_as_if_complete():
    incident, _, _, service, responder = ir.open_incident()
    incident.scope = replace(incident.scope, complete=False)
    plan = ir.approved_plan(incident, service, responder)
    assert service.execute(incident, plan, responder, ir.SyntheticConnector(), now=111).reason == "scope-incomplete"


@pytest.mark.parametrize("outcome,verified", [
    (ir.ActionOutcome.FAILED, False),
    (ir.ActionOutcome.UNKNOWN, False),
    (ir.ActionOutcome.SUCCESS, False),
])
def test_partial_or_unverified_containment_remains_incomplete(outcome, verified):
    incident, _, _, service, responder = ir.open_incident()
    connector = ir.SyntheticConnector({ir.Action.BLOCK_DESTINATION: (outcome, verified)})
    result = service.execute(incident, ir.approved_plan(incident, service, responder),
                             responder, connector, now=111)
    assert result.reason == "containment-incomplete"
    assert incident.state is ir.IncidentState.CONTAINMENT_INCOMPLETE


def test_connector_exception_becomes_unknown_not_fabricated_success():
    incident, _, _, service, responder = ir.open_incident()
    connector = ir.SyntheticConnector(raise_actions=frozenset({ir.Action.REVOKE_CREDENTIAL}))
    result = service.execute(incident, ir.approved_plan(incident, service, responder),
                             responder, connector, now=111)
    credential = next(receipt for receipt in result.receipts
                      if receipt.action is ir.Action.REVOKE_CREDENTIAL)
    assert credential.outcome is ir.ActionOutcome.UNKNOWN
    assert credential.reason == "connector-exception"
    assert incident.state is ir.IncidentState.CONTAINMENT_INCOMPLETE


def test_recovery_requires_verified_containment():
    incident, _, _, service, _ = ir.open_incident()
    approver = ir.Responder("risk:north:2", "north", frozenset({"recovery_approver"}))
    with pytest.raises(RuntimeError, match="verified-containment-required"):
        ir.prepare_recovery_handoff(
            incident, approver, root_cause_evidence_id="root", remediation_id="fix",
            regression_suite_id="suite", policy_version=service.current_policy_version,
            current_policy_version=service.current_policy_version,
        )


def test_recovery_requires_separate_role_tenant_and_current_policy():
    incident, _, _, service, commander = ir.open_incident()
    service.execute(incident, ir.approved_plan(incident, service, commander),
                    commander, ir.SyntheticConnector(), now=111)
    with pytest.raises(PermissionError, match="recovery-approver-required"):
        ir.prepare_recovery_handoff(
            incident, commander, root_cause_evidence_id="root", remediation_id="fix",
            regression_suite_id="suite", policy_version=service.current_policy_version,
            current_policy_version=service.current_policy_version,
        )
    dual_role = replace(commander, roles=frozenset({"incident_commander", "recovery_approver"}))
    with pytest.raises(PermissionError, match="recovery-separation-required"):
        ir.prepare_recovery_handoff(
            incident, dual_role, root_cause_evidence_id="root", remediation_id="fix",
            regression_suite_id="suite", policy_version=service.current_policy_version,
            current_policy_version=service.current_policy_version,
        )
    approver = ir.Responder("risk:south:2", "south", frozenset({"recovery_approver"}))
    with pytest.raises(PermissionError, match="tenant-mismatch"):
        ir.prepare_recovery_handoff(
            incident, approver, root_cause_evidence_id="root", remediation_id="fix",
            regression_suite_id="suite", policy_version=service.current_policy_version,
            current_policy_version=service.current_policy_version,
        )
    approver = replace(approver, tenant="north")
    with pytest.raises(PermissionError, match="recovery-policy-stale"):
        ir.prepare_recovery_handoff(
            incident, approver, root_cause_evidence_id="root", remediation_id="fix",
            regression_suite_id="suite", policy_version="old",
            current_policy_version=service.current_policy_version,
        )


def test_recovery_handoff_does_not_claim_incident_resolved():
    incident, _, _, service, commander = ir.open_incident()
    service.execute(incident, ir.approved_plan(incident, service, commander),
                    commander, ir.SyntheticConnector(), now=111)
    approver = ir.Responder("risk:north:2", "north", frozenset({"recovery_approver"}))
    handoff = ir.prepare_recovery_handoff(
        incident, approver, root_cause_evidence_id="root", remediation_id="fix",
        regression_suite_id="suite", policy_version=service.current_policy_version,
        current_policy_version=service.current_policy_version,
    )
    assert handoff.incident_id == incident.incident_id
    assert incident.state is ir.IncidentState.RECOVERY_READY
    assert incident.state is not ir.IncidentState.RESOLVED


def test_evidence_vault_detects_chain_tampering():
    vault = ir.EvidenceVault()
    vault.append("incident:1", "alert", {"evidence": "1"})
    vault.append("incident:1", "receipt", {"action": "disable"})
    assert vault.verify()
    vault.records[0] = replace(vault.records[0], payload_digest="tampered")
    assert not vault.verify()


def test_real_opentelemetry_adapter_keeps_tenant_authority_outside_span():
    proof = otel_adapter.run_demo()
    assert proof["trace_id"] == "11111111111111111111111111111111"
    assert proof["declared_tenant_ignored"]
    assert proof["trusted_tenant"] == "north"
    assert proof["admission"] == "admitted"
    assert proof["model_summary_is_authority"] is False


def test_evaluation_uses_declared_populations_and_exact_outcomes():
    report = ir.evaluate_controls()
    assert (report.valid_cases, report.attack_cases, report.boundary_cases,
            report.failure_cases) == (2, 1, 1, 1)
    assert report.incident_detection_recall == 1
    assert report.benign_promotion_rate == 0
    assert report.unauthorized_signal_admission_rate == 0
    assert report.duplicate_incident_rate == 0
    assert report.verified_containment_rate == 0
    assert report.recovery_without_containment_rate == 0
