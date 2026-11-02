"""Run the complete credential-free Enterprise 03 incident-response proof."""
from dataclasses import asdict
import json

import incident_response as ir
import otel_adapter


def main() -> None:
    incident, _, _, service, commander = ir.open_incident()
    assert incident.model_summary == "Model recommends resolving immediately"
    assert incident.state is ir.IncidentState.TRIAGED

    vault = ir.EvidenceVault()
    vault.append(incident.incident_id, "admitted-evidence", incident.evidence_ids)
    plan = ir.approved_plan(incident, service, commander)
    connector = ir.SyntheticConnector()
    result = service.execute(incident, plan, commander, connector, now=111)
    vault.append(incident.incident_id, "containment-receipts", result.receipts)
    assert result.incident_state is ir.IncidentState.CONTAINED
    assert vault.verify()

    recovery_approver = ir.Responder(
        "risk:north:2", "north", frozenset({"recovery_approver"})
    )
    handoff = ir.prepare_recovery_handoff(
        incident, recovery_approver,
        root_cause_evidence_id="evidence:root-cause:42",
        remediation_id="remediation:prompt-source:42",
        regression_suite_id="suite:incident-42",
        policy_version=service.current_policy_version,
        current_policy_version=service.current_policy_version,
    )
    assert incident.state is ir.IncidentState.RECOVERY_READY

    report = ir.evaluate_controls()
    sdk = otel_adapter.run_demo()
    assert report.incident_detection_recall == 1
    assert report.benign_promotion_rate == 0
    assert report.unauthorized_signal_admission_rate == 0
    assert report.duplicate_incident_rate == 0
    assert report.verified_containment_rate == 0  # injected unknown connector
    assert report.recovery_without_containment_rate == 0
    assert sdk["declared_tenant_ignored"] and sdk["admission"] == "admitted"

    print(json.dumps({
        "incident": {
            "id": incident.incident_id,
            "state": incident.state.value,
            "version": incident.version,
            "scope_digest": incident.scope.scope_digest,
        },
        "containment": {
            "reason": result.reason,
            "receipts": [asdict(receipt) for receipt in result.receipts],
        },
        "recovery_handoff": asdict(handoff),
        "vault_chain_valid": vault.verify(),
        "evaluation": asdict(report),
        "opentelemetry": {key: value for key, value in sdk.items() if key != "evidence"},
    }, indent=2, default=lambda item: item.value))


if __name__ == "__main__":
    main()
