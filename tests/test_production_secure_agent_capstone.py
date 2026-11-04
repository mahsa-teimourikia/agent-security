"""Security and release invariants for Enterprise Course 09."""
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/09-production-secure-agent-capstone"
sys.path.insert(0, str(ROOT))
import production_capstone as core  # noqa: E402
import capstone_fixtures as fixtures  # noqa: E402
import sdk_adapter  # noqa: E402
from capstone_otel import CapstoneTelemetry  # noqa: E402

LAB_SPEC = importlib.util.spec_from_file_location("enterprise_09_course_lab", ROOT / "lab.py")
assert LAB_SPEC and LAB_SPEC.loader
course_lab = importlib.util.module_from_spec(LAB_SPEC)
sys.modules[LAB_SPEC.name] = course_lab
LAB_SPEC.loader.exec_module(course_lab)


def dispatch_with_approval(control, value=None, *, actor="runtime", grant="grant:runtime", now=fixtures.NOW):
    identities = fixtures.actors()
    value = value or fixtures.proposal()
    receipt = control.issue_approval(
        identities["approver"], identities[actor].subject, value,
        approval_id=f"approval:{value.request_id}", now=fixtures.NOW,
    )
    return control.dispatch(
        identities[actor], value, grant_id=grant, approval_id=receipt.approval_id, now=now,
    )


def test_attack_suite_has_exact_declared_populations_and_denominators():
    results = course_lab.run_attack_suite()
    evaluation = course_lab.evaluate_suite(results)
    assert set(evaluation.covered_case_ids) == core.REQUIRED_CASE_IDS
    assert (evaluation.total_cases, evaluation.valid_cases, evaluation.attack_cases, evaluation.failure_cases) == (16, 2, 11, 3)
    assert (evaluation.valid_successes, evaluation.attacks_safely_blocked, evaluation.failures_safely_handled) == (2, 11, 3)
    assert evaluation.cost_per_successful_compliant_task == 10.5


def test_attack_suite_preserves_utility_without_forbidden_outcomes():
    evaluation = course_lab.evaluate_suite()
    assert evaluation.valid_success_rate == evaluation.attack_block_rate == evaluation.failure_safe_rate == 1.0
    assert evaluation.forbidden_outcomes == evaluation.false_blocks == 0


def test_retrieval_authorizes_before_ranking_and_keeps_hostile_text_as_data():
    result = fixtures.plane().retrieve(
        fixtures.actors()["runtime"],
        ("doc:north:case-42", "doc:north:hostile", "doc:south:secret"),
        subject_id="case:north:42", now=fixtures.NOW,
    )
    assert result.decision is core.Decision.ALLOW
    assert result.document_ids == ("doc:north:case-42", "doc:north:hostile")
    assert "IGNORE POLICY" in result.contents[1]


def test_retrieval_policy_outage_is_unknown():
    result = fixtures.plane(policy_available=False).retrieve(
        fixtures.actors()["runtime"], ("doc:north:case-42",),
        subject_id="case:north:42", now=fixtures.NOW,
    )
    assert (result.decision, result.reason) == (core.Decision.UNKNOWN, "policy-unavailable")


@pytest.mark.parametrize("kind", ["approval", "authority", "credential", "policy"])
def test_memory_cannot_persist_authority_or_secrets(kind):
    actor = fixtures.actors()["runtime"]
    candidate = core.MemoryCandidate("memory:1", "north", actor.subject, kind, "claim", "source:1", "v1")
    assert fixtures.plane().admit_memory(actor, candidate).reason == "memory-kind-forbidden"


@pytest.mark.parametrize("source_id,source_version", [("", "v1"), ("source:1", "")])
def test_memory_requires_provenance(source_id, source_version):
    actor = fixtures.actors()["runtime"]
    candidate = core.MemoryCandidate("memory:1", "north", actor.subject, "preference", "compact", source_id, source_version)
    assert fixtures.plane().admit_memory(actor, candidate).reason == "memory-provenance"


def test_scoped_provenanced_preference_memory_is_admitted():
    actor = fixtures.actors()["runtime"]
    candidate = core.MemoryCandidate("memory:1", "north", actor.subject, "preference", "compact", "user:setting", "v3")
    control = fixtures.plane()
    assert control.admit_memory(actor, candidate).decision is core.Decision.ALLOW
    assert control.memory["memory:1"] == candidate


@pytest.mark.parametrize("change", [
    {"authenticated": False},
    {"tenant": "south"},
    {"roles": frozenset()},
    {"subject": "user:north:alice"},
])
def test_approval_requires_authenticated_separate_effect_approver(change):
    actor = replace(fixtures.actors()["approver"], **change)
    with pytest.raises(PermissionError, match="approval-not-authorized"):
        fixtures.plane().issue_approval(actor, "user:north:alice", fixtures.proposal(), approval_id="a", now=fixtures.NOW)


def test_tampered_proposal_cannot_be_approved():
    tampered = replace(fixtures.proposal(), arguments={"status": "resolved"})
    with pytest.raises(PermissionError, match="approval-not-authorized"):
        fixtures.plane().issue_approval(
            fixtures.actors()["approver"], fixtures.actors()["runtime"].subject,
            tampered, approval_id="a", now=fixtures.NOW,
        )


@pytest.mark.parametrize("change", [
    {"principal": "user:north:bob"},
    {"operation": "refund.issue"},
    {"resource_id": "case:north:99"},
    {"policy_version": "policy-old"},
    {"expires_at": fixtures.NOW},
])
def test_approval_is_exact_current_and_expiring(change):
    identities = fixtures.actors()
    control = fixtures.plane()
    value = fixtures.proposal()
    approval = control.issue_approval(
        identities["approver"], identities["runtime"].subject, value,
        approval_id="approval:exact", now=fixtures.NOW,
    )
    control.approvals[approval.approval_id] = replace(approval, **change)
    result = control.dispatch(
        identities["runtime"], value, grant_id="grant:runtime",
        approval_id=approval.approval_id, now=fixtures.NOW,
    )
    assert (result.decision, result.reason) == (core.Decision.DENY, "approval-binding")


def test_approval_proof_tampering_is_denied():
    identities = fixtures.actors()
    control = fixtures.plane()
    value = fixtures.proposal()
    approval = control.issue_approval(identities["approver"], identities["runtime"].subject, value, approval_id="a", now=fixtures.NOW)
    control.approvals["a"] = replace(approval, proof="0" * 64)
    assert control.dispatch(identities["runtime"], value, grant_id="grant:runtime", approval_id="a", now=fixtures.NOW).reason == "approval-binding"


@pytest.mark.parametrize("change", [
    {"parent_subject": "user:north:bob"}, {"delegate_workload": "workload:other"}, {"tenant": "south"},
    {"audience": "other-gateway"}, {"policy_version": "policy-old"},
    {"expires_at": fixtures.NOW}, {"revocation_epoch": 1},
])
def test_delegation_grant_is_bound_and_current(change):
    control = fixtures.plane()
    control.grants["grant:runtime"] = replace(control.grants["grant:runtime"], **change)
    result = control.dispatch(fixtures.actors()["runtime"], fixtures.proposal(), grant_id="grant:runtime", approval_id=None, now=fixtures.NOW)
    assert result.reason == "grant-binding"


def test_capability_escalation_is_denied():
    value = fixtures.proposal(operation="refund.issue")
    result = fixtures.plane().dispatch(fixtures.actors()["runtime"], value, grant_id="grant:runtime", approval_id=None, now=fixtures.NOW)
    assert result.reason == "capability-escalation"


@pytest.mark.parametrize("key", sorted(core.FORBIDDEN_ARGUMENT_KEYS))
def test_credentials_cannot_enter_model_visible_arguments(key):
    value = fixtures.proposal(arguments={"status": "resolved", key: "synthetic"})
    result = fixtures.plane().dispatch(fixtures.actors()["runtime"], value, grant_id="grant:runtime", approval_id=None, now=fixtures.NOW)
    assert result.reason == "credential-in-arguments"


@pytest.mark.parametrize("server_change,proposal_change,reason", [
    ({"enabled": False}, {}, "mcp-server-untrusted"),
    ({"tenant": "south"}, {}, "mcp-server-untrusted"),
    ({"expires_at": fixtures.NOW}, {}, "mcp-server-integrity"),
    ({}, {"mcp_server_digest": "sha256:replacement"}, "mcp-server-integrity"),
    ({"tools": frozenset()}, {}, "mcp-tool-not-allowed"),
])
def test_mcp_admission_is_pinned_current_and_tool_scoped(server_change, proposal_change, reason):
    control = fixtures.plane()
    control.servers["mcp:case-service"] = replace(control.servers["mcp:case-service"], **server_change)
    result = control.dispatch(fixtures.actors()["runtime"], fixtures.proposal(**proposal_change), grant_id="grant:runtime", approval_id=None, now=fixtures.NOW)
    assert result.reason == reason


def test_confirmed_effect_is_idempotent_and_not_replayed():
    control = fixtures.plane()
    value = fixtures.proposal()
    first = dispatch_with_approval(control, value)
    retry = control.dispatch(fixtures.actors()["runtime"], value, grant_id="grant:runtime", approval_id=None, now=fixtures.NOW)
    assert first.decision is core.Decision.ALLOW
    assert (retry.decision, retry.effect_id) == (core.Decision.IDEMPOTENT, first.effect_id)
    assert len(control.effects) == 1


def test_logical_operation_collision_is_denied():
    control = fixtures.plane()
    original = fixtures.proposal()
    dispatch_with_approval(control, original)
    changed = fixtures.proposal(request_id="request:changed", arguments={"status": "resolved", "note": "changed"})
    assert control.dispatch(fixtures.actors()["runtime"], changed, grant_id="grant:runtime", approval_id=None, now=fixtures.NOW).reason == "operation-id-collision"


def test_unknown_provider_outcome_requires_reconciliation_before_retry():
    control = fixtures.plane()
    value = fixtures.proposal()
    assert fixtures.approved_dispatch(control, proposal_value=value, provider_outcome="unknown").reason == "provider-outcome-unknown"
    retry = control.dispatch(fixtures.actors()["runtime"], value, grant_id="grant:runtime", approval_id=None, now=fixtures.NOW)
    assert (retry.decision, retry.reason) == (core.Decision.UNKNOWN, "reconciliation-required")
    assert control.reconcile(value.logical_operation_id, provider_committed=True).reason == "provider-commit-reconciled"


@pytest.mark.parametrize("actor", ["runtime", "approver", "recovery"])
def test_only_incident_commander_can_activate_kill_switch(actor):
    with pytest.raises(PermissionError, match="kill-switch-not-authorized"):
        fixtures.plane().activate_kill_switch(fixtures.actors()[actor])


def test_kill_switch_revokes_in_flight_effect_and_recovery_advances_epoch():
    control = fixtures.plane()
    value = fixtures.proposal()
    identities = fixtures.actors()
    approval = control.issue_approval(identities["approver"], identities["runtime"].subject, value, approval_id="a", now=fixtures.NOW)
    control.activate_kill_switch(identities["incident"])
    assert control.dispatch(identities["runtime"], value, grant_id="grant:runtime", approval_id=approval.approval_id, now=fixtures.NOW).reason == "control-epoch"
    control.recover(identities["recovery"])
    assert (control.kill_active, control.control_epoch) == (False, 2)


@pytest.mark.parametrize("change,reason", [
    ({"state": {"step": "tampered"}}, "checkpoint-integrity"),
    ({"policy_version": "policy-old"}, "checkpoint-policy-stale"),
    ({"control_epoch": 9}, "checkpoint-control-epoch"),
])
def test_checkpoint_resume_revalidates_integrity_policy_and_epoch(change, reason):
    control = fixtures.plane()
    checkpoint = control.create_checkpoint(fixtures.actors()["runtime"], "run:1", {"step": "draft"})
    assert control.resume(fixtures.actors()["runtime"], replace(checkpoint, **change)).reason == reason


def test_checkpoint_waits_for_ambiguous_effect_reconciliation():
    control = fixtures.plane()
    fixtures.approved_dispatch(control, provider_outcome="unknown")
    checkpoint = control.create_checkpoint(fixtures.actors()["runtime"], "run:1", {"step": "effect"})
    result = control.resume(fixtures.actors()["runtime"], checkpoint)
    assert (result.decision, result.reason) == (core.Decision.UNKNOWN, "checkpoint-reconciliation-required")


def test_release_gate_accepts_complete_exact_current_evidence_only():
    evaluation = course_lab.evaluate_suite()
    receipt = fixtures.gate().evaluate(fixtures.dossier(evaluation), now=fixtures.NOW)
    assert (receipt.state, receipt.reason) == (core.GateState.READY, "technical-readiness-proven")


@pytest.mark.parametrize("change", [
    {"authenticated": False}, {"tenant": "south"},
    {"subject_digest": "sha256:other"}, {"policy_version": "policy-old"},
    {"expires_at": fixtures.NOW}, {"details_digest": ""},
])
def test_invalid_evidence_makes_release_incomplete(change):
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    evidence = (replace(dossier.evidence[0], **change),) + dossier.evidence[1:]
    receipt = fixtures.gate().evaluate(replace(dossier, evidence=evidence), now=fixtures.NOW)
    assert receipt.state is core.GateState.INCOMPLETE
    assert dossier.evidence[0].evidence_id in receipt.invalid_evidence_ids


def test_duplicate_evidence_is_rejected():
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    with pytest.raises(ValueError, match="duplicate-evidence"):
        fixtures.gate().evaluate(replace(dossier, evidence=dossier.evidence + (dossier.evidence[0],)), now=fixtures.NOW)


def test_missing_evidence_kind_is_incomplete():
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    receipt = fixtures.gate().evaluate(replace(dossier, evidence=dossier.evidence[1:]), now=fixtures.NOW)
    assert receipt.state is core.GateState.INCOMPLETE
    assert receipt.missing_kinds


def test_severe_failure_is_noncompensable_blocker():
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    evidence = tuple(replace(item, result="fail", severe=True) if item.kind == "attack-suite" else item for item in dossier.evidence)
    assert fixtures.gate().evaluate(replace(dossier, evidence=evidence), now=fixtures.NOW).state is core.GateState.BLOCKED


def test_unknown_evidence_is_incomplete_not_pass_or_fail():
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    evidence = tuple(replace(item, result="unknown") if item.kind == "telemetry" else item for item in dossier.evidence)
    assert fixtures.gate().evaluate(replace(dossier, evidence=evidence), now=fixtures.NOW).reason == "release-evidence-unknown"


@pytest.mark.parametrize("risk_change", [
    {"owner": ""}, {"decision": "ignore"}, {"expires_at": fixtures.NOW},
    {"evidence_ids": ()}, {"evidence_ids": ("evidence:missing",)},
])
def test_residual_risk_requires_owner_bounded_decision_and_evidence(risk_change):
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    risks = (replace(dossier.residual_risks[0], **risk_change),)
    assert fixtures.gate().evaluate(replace(dossier, residual_risks=risks), now=fixtures.NOW).state is core.GateState.INCOMPLETE


@pytest.mark.parametrize("change", [
    {"dossier_id": ""}, {"architecture_version": ""}, {"tenant": "south"},
    {"candidate_digest": "sha256:other"}, {"policy_version": "policy-old"},
    {"control_epoch": 1}, {"requested_decision": "observe"},
])
def test_release_dossier_binding_failure_blocks(change):
    dossier = fixtures.dossier(course_lab.evaluate_suite(), **change)
    assert fixtures.gate().evaluate(dossier, now=fixtures.NOW).state is core.GateState.BLOCKED


def test_missing_required_case_is_incomplete():
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    evaluation = replace(dossier.evaluation, covered_case_ids=dossier.evaluation.covered_case_ids[:-1], total_cases=15)
    assert fixtures.gate().evaluate(replace(dossier, evaluation=evaluation), now=fixtures.NOW).state is core.GateState.INCOMPLETE


@pytest.mark.parametrize("change", [
    {"valid_cases": 3}, {"valid_successes": 3}, {"attacks_safely_blocked": 12},
    {"failures_safely_handled": 4}, {"total_cost_units": -1},
    {"successful_compliant_tasks": 1},
])
def test_inconsistent_evaluation_accounting_is_incomplete(change):
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    evaluation = replace(dossier.evaluation, **change)
    assert fixtures.gate().evaluate(replace(dossier, evaluation=evaluation), now=fixtures.NOW).state is core.GateState.INCOMPLETE


@pytest.mark.parametrize("change", [
    {"forbidden_outcomes": 1}, {"false_blocks": 1},
    {"valid_successes": 1, "successful_compliant_tasks": 1},
])
def test_failed_security_or_utility_population_blocks_release(change):
    dossier = fixtures.dossier(course_lab.evaluate_suite())
    assert fixtures.gate().evaluate(replace(dossier, evaluation=replace(dossier.evaluation, **change)), now=fixtures.NOW).state is core.GateState.BLOCKED


def test_sdk_adapter_is_strict_requires_approval_and_performs_no_model_or_network_call():
    proof = sdk_adapter.credential_free_demo()
    assert proof["strict_schema"] and proof["needs_approval"]
    assert proof["handoff_count"] == 1
    assert proof["decision"] == "allow"
    assert proof["model_calls"] == proof["network_calls"] == 0


def test_sdk_schema_rejects_extra_fields_and_coercion():
    payload = {"case_id": "case:north:42", "status": "resolved", "note": "ok", "logical_operation_id": "operation:sdk:42", "tenant": "north"}
    with pytest.raises(ValidationError):
        sdk_adapter.CaseUpdateInput.model_validate(payload, strict=True)
    payload.pop("tenant")
    payload["note"] = 42
    with pytest.raises(ValidationError):
        sdk_adapter.CaseUpdateInput.model_validate(payload, strict=True)


def test_opentelemetry_adapter_emits_minimized_decision_fields_only():
    receipt = fixtures.approved_dispatch(fixtures.plane())
    telemetry = CapstoneTelemetry()
    telemetry.emit(receipt)
    attributes = dict(telemetry.finished()[0].attributes)
    assert attributes["agent.decision"] == "allow"
    assert attributes["agent.evidence.count"] == 1
    assert not any("prompt" in key or "content" in key or "argument" in key for key in attributes)


def test_legacy_claim_shape_never_grants_readiness():
    result = course_lab.assess({})
    assert not result["ready"]
    assert result["missing"]


def test_lab_runs_ready_blocked_and_incomplete_paths_end_to_end():
    result = course_lab.run_lab()
    assert result["ready_gate"]["state"] is core.GateState.READY
    assert result["severe_failure_gate"]["state"] is core.GateState.BLOCKED
    assert result["missing_evidence_gate"]["state"] is core.GateState.INCOMPLETE
