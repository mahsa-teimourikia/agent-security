"""Generate the Enterprise 03 notebook deterministically."""
from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "incident_containment.ipynb"


def markdown(cell_id: str, source: str):
    cell = nbf.v4.new_markdown_cell(source.strip())
    cell["id"] = cell_id
    return cell


def code(cell_id: str, source: str):
    cell = nbf.v4.new_code_cell(source.strip())
    cell["id"] = cell_id
    return cell


def build_notebook():
    notebook = nbf.v4.new_notebook()
    notebook["metadata"] = {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        markdown("e03-title", """
# Enterprise 03 — Agent Incident Detection and Containment

**Goal:** turn observable signals into admitted evidence, versioned detection,
one tenant-bound incident, exact authorized containment, verified
postconditions, and a governed recovery handoff.

This notebook is deterministic, credential-free, and makes no external calls.
It uses a real OpenTelemetry Python SDK span with an in-memory exporter.

![Incident evidence admission, detection, containment, and recovery handoff](architecture.svg)
"""),
        markdown("e03-thesis", """
## Security thesis

Telemetry and model summaries are evidence inputs, not authority. The trusted
application authenticates producers, admits evidence, versions detection,
computes tenant scope, authorizes exact actions, verifies connector
postconditions, and preserves honest incident state. Recovery readiness does
not itself resume work, replay an effect, or resolve an incident.
"""),
        code("e03-imports", """
from dataclasses import asdict, replace
import json

import incident_response as ir

producer, store, detector, graph, manager = ir.build_system()
print({"producer": producer.producer_id, "tenant": producer.tenant,
       "rule": detector.rule_id, "rule_version": detector.rule_version})
"""),
        markdown("e03-otel", """
## 1. Capture a real OpenTelemetry span

The span includes a deliberately false declared tenant. The adapter uses the
transport-bound tenant supplied by the trusted application, not that attribute.
OpenTelemetry provides interoperable telemetry; it does not decide incident
truth or response authority.
"""),
        code("e03-otel-run", """
import otel_adapter

sdk_proof = otel_adapter.run_demo()
print(json.dumps({key: value for key, value in sdk_proof.items() if key != "evidence"}, indent=2))
assert sdk_proof["trace_id"] == "11111111111111111111111111111111"
assert sdk_proof["declared_tenant_ignored"]
assert sdk_proof["trusted_tenant"] == "north"
assert sdk_proof["model_summary_is_authority"] is False
"""),
        markdown("e03-admission", """
## 2. Admit authenticated, current, complete evidence

The course HMAC is an offline analogue for protected producer identity and
integrity. Admission also binds tenant, freshness, required fields, and a stable
source digest. No prompt or chain-of-thought is retained.
"""),
        code("e03-admission-run", """
signal = ir.signed_signal(producer)
receipt = store.admit(signal, received_at=101)
evidence = store.evidence[receipt.evidence_id]
print(json.dumps(asdict(evidence), indent=2, default=lambda item: item.value))
assert receipt.status is ir.Admission.ADMITTED
assert evidence.tenant == producer.tenant
"""),
        markdown("e03-attacks", """
## 3. Reject tamper, tenant substitution, and stale evidence

Producer authentication is necessary but insufficient: the event must still
match its producer tenant and freshness window, and the signature must cover
the normalized content.
"""),
        code("e03-attacks-run", """
attack_producer, attack_store, *_ = ir.build_system()
tampered = replace(ir.signed_signal(attack_producer, event_id="event:tampered"),
                   destination="changed.evil")
cross_tenant = ir.signed_signal(attack_producer, event_id="event:south", tenant="south")
old = ir.signed_signal(attack_producer, event_id="event:old", occurred_at=-201)
results = [
    attack_store.admit(tampered, received_at=101),
    attack_store.admit(cross_tenant, received_at=101),
    attack_store.admit(old, received_at=101),
]
print([item.reason for item in results])
assert [item.reason for item in results] == [
    "invalid-signal-signature", "producer-tenant-mismatch", "signal-too-old"]
"""),
        markdown("e03-dedup", """
## 4. Distinguish duplicate delivery from content conflict

Identical redelivery reuses one admitted evidence record. Reusing the event ID
with different signed content is rejected as an integrity conflict.
"""),
        code("e03-dedup-run", """
duplicate = store.admit(signal, received_at=102)
conflict_signal = ir.SignalSigner.sign(
    replace(signal, destination="other.evil", signature=""), producer)
conflict = store.admit(conflict_signal, received_at=102)
print({"duplicate": duplicate.reason, "conflict": conflict.reason,
       "evidence_records": len(store.evidence)})
assert duplicate.status is ir.Admission.IDEMPOTENT
assert conflict.reason == "event-id-conflict"
assert len(store.evidence) == 1
"""),
        markdown("e03-detection", """
## 5. Bind detection to rule version and exact evidence

The rule matches only a committed effect to an unapproved destination. A safe
destination, denied effect, or uncommitted attempt belongs to a different
population and must not inflate recall or false-positive metrics.
"""),
        code("e03-detection-run", """
alert = detector.detect(evidence)
benign_signal = ir.signed_signal(producer, event_id="event:benign",
                                 destination="support.internal")
benign_receipt = store.admit(benign_signal, received_at=101)
benign_alert = detector.detect(store.evidence[benign_receipt.evidence_id])
print({"alert": alert.alert_id, "rule": alert.rule_id,
       "version": alert.rule_version, "benign_alert": benign_alert})
assert alert.evidence_ids == (evidence.evidence_id,)
assert benign_alert is None
"""),
        markdown("e03-incident", """
## 6. Open one incident; keep model text non-authoritative

The stable fingerprint deduplicates promotion. The stored model recommendation
is an analyst aid and cannot move the state from `triaged`.
"""),
        code("e03-incident-run", """
scope = graph.scope(alert)
incident = manager.promote(alert, scope, model_summary="Resolve immediately")
same_incident = manager.promote(alert, scope, model_summary="Different model text")
print({"incident": incident.incident_id, "state": incident.state.value,
       "model_summary": incident.model_summary, "count": len(manager.incidents)})
assert same_incident is incident
assert incident.state is ir.IncidentState.TRIAGED
assert len(manager.incidents) == 1
"""),
        markdown("e03-scope", """
## 7. Preserve incomplete scope

The trusted graph binds the run to agent, credential, queue, and tenant. If that
mapping is missing, the course does not interpret empty credentials or queues
as safe; it marks the scope incomplete and denies the default plan.
"""),
        code("e03-scope-run", """
complete = graph.scope(alert)
incomplete = ir.AssetGraph({}).scope(alert)
print({"complete": asdict(complete), "incomplete": asdict(incomplete)})
assert complete.complete
assert not incomplete.complete
assert not incomplete.credential_ids
"""),
        markdown("e03-plan", """
## 8. Bind one plan to current incident, scope, policy, approver, and time

The full action set disables the agent, revokes writes and credentials, blocks
the destination, and pauses the queue. A changed incident version or scope
invalidates the signed plan.
"""),
        code("e03-plan-run", """
service = ir.ContainmentService()
commander = ir.Responder("commander:north:1", "north",
                          frozenset({"incident_commander"}))
plan = ir.approved_plan(incident, service, commander)
print({"plan": plan.plan_id, "incident_version": plan.expected_incident_version,
       "actions": [action.value for action in plan.actions],
       "signature_valid": service.signer.verify(plan)})
assert service.signer.verify(plan)
assert set(plan.actions) == set(ir.Action)
"""),
        markdown("e03-contain", """
## 9. Execute and verify five independent controls

Stable operation IDs make connector redelivery idempotent. The incident becomes
contained only when every connector reports success and the application verifies
the corresponding postcondition.
"""),
        code("e03-contain-run", """
connector = ir.SyntheticConnector()
result = service.execute(incident, plan, commander, connector, now=111)
print(json.dumps({"reason": result.reason, "state": result.incident_state.value,
                  "receipts": [asdict(item) for item in result.receipts]},
                 indent=2, default=lambda item: item.value))
assert result.incident_state is ir.IncidentState.CONTAINED
assert len(result.receipts) == 5
assert all(item.verified for item in result.receipts)
"""),
        markdown("e03-failure", """
## 10. Expose partial failure and block recovery

A destination connector times out. Other controls remain in place, but the
incident is `containment-incomplete`. Unknown is not converted to success, and
recovery evidence cannot bypass that state.
"""),
        code("e03-failure-run", """
failed_incident, _, _, failed_service, failed_commander = ir.open_incident()
failed_connector = ir.SyntheticConnector({
    ir.Action.BLOCK_DESTINATION: (ir.ActionOutcome.UNKNOWN, False)})
failed_result = failed_service.execute(
    failed_incident,
    ir.approved_plan(failed_incident, failed_service, failed_commander),
    failed_commander, failed_connector, now=111)
print({"state": failed_result.incident_state.value,
       "failed": [(r.action.value, r.outcome.value, r.verified)
                  for r in failed_result.receipts if not r.verified]})
assert failed_incident.state is ir.IncidentState.CONTAINMENT_INCOMPLETE
"""),
        markdown("e03-vault", """
## 11. Preserve a digest-linked evidence chain

The chain detects mutation while avoiding raw prompts, credentials, and private
reasoning. Production still needs durable storage, legal hold, trusted time,
access control, and independent attestation.
"""),
        code("e03-vault-run", """
vault = ir.EvidenceVault()
vault.append(incident.incident_id, "admitted-evidence", incident.evidence_ids)
vault.append(incident.incident_id, "containment-receipts", incident.action_receipts)
valid_before = vault.verify()
vault.records[0] = replace(vault.records[0], payload_digest="tampered")
valid_after = vault.verify()
print({"before_tamper": valid_before, "after_tamper": valid_after})
assert valid_before and not valid_after
"""),
        markdown("e03-recovery", """
## 12. Prepare recovery without claiming resolution

A different role supplies root-cause, remediation, regression, and current
policy evidence. The output is a handoff. It does not re-enable the agent,
credential, queue, or destination, and it does not mark the incident resolved.
"""),
        code("e03-recovery-run", """
recovery_approver = ir.Responder(
    "risk:north:2", "north", frozenset({"recovery_approver"}))
handoff = ir.prepare_recovery_handoff(
    incident, recovery_approver,
    root_cause_evidence_id="evidence:root-cause:42",
    remediation_id="remediation:ticket-source:42",
    regression_suite_id="suite:incident-42",
    policy_version=service.current_policy_version,
    current_policy_version=service.current_policy_version)
print(json.dumps(asdict(handoff), indent=2))
assert incident.state is ir.IncidentState.RECOVERY_READY
assert incident.state is not ir.IncidentState.RESOLVED
"""),
        markdown("e03-metrics", """
## 13. Evaluate distinct populations and exact denominators

The failure fixture intentionally produces zero verified containment. That is a
correct result, not a failing test. Valid detection cannot average away a
containment gap or recovery bypass.
"""),
        code("e03-metrics-run", """
report = ir.evaluate_controls()
print(json.dumps(asdict(report), indent=2))
assert (report.valid_cases, report.attack_cases,
        report.boundary_cases, report.failure_cases) == (2, 1, 1, 1)
assert report.incident_detection_recall == 1
assert report.benign_promotion_rate == 0
assert report.unauthorized_signal_admission_rate == 0
assert report.duplicate_incident_rate == 0
assert report.verified_containment_rate == 0
assert report.recovery_without_containment_rate == 0
"""),
        markdown("e03-production", """
## Production upgrade and checkpoint

Replace the HMAC fixture with mTLS/workload identity and protected keys; memory
state with durable, access-controlled stores; the static graph with current
CMDB/identity/workflow relationships; synthetic connectors with IAM, scheduler,
credential, gateway, queue, and network APIs; and local checks with independent
authoritative postconditions.

**Checkpoint:** add a credential-anomaly rule and correlate it with committed
egress without double-counting one source. Expand scope and produce a new plan
digest. Test wrong tenant, ID conflict, late data, stale incident version,
unknown credential revocation, and recovery bypass. Pass only when incomplete
evidence stays explicit and no model text, event attribute, or connector success
acts as authority.
"""),
    ]
    return notebook


def main() -> None:
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")


if __name__ == "__main__":
    main()
