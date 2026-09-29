"""Focused invariants for Intermediate 03 agent identity and delegation."""
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "03-agent-identity-and-delegated-authority"
SPEC = importlib.util.spec_from_file_location("intermediate_03_identity_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def test_declared_evaluation_separates_valid_attacks_and_failures() -> None:
    report, observations = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (18, 4, 12, 2)
    assert report.valid_task_success_rate == report.trace_completeness_rate == 1.0
    assert report.authority_escalation_success_rate == 0.0
    assert report.cross_tenant_disclosure_rate == 0.0
    assert report.proof_replay_acceptance_rate == 0.0
    assert report.sender_constraint_detection_rate == 1.0
    assert report.baseline_attack_acceptance_rate == 1.0
    assert all(item.terminal_status == "error" for item in observations if item.kind is LAB.CaseKind.FAILURE)


def test_two_hop_path_preserves_subject_and_shrinks_actor_authority() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.read_attachment(
        session_id="session:alice", agent_attestation_id="attest:support",
        attachment_id="attachment:north:7", request_id="test:path", now=LAB.NOW,
    )
    assert response.status is LAB.DecisionStatus.ALLOW
    assert response.content == "Synthetic Northwind case attachment"
    root, child = (scenario.grants.grants[item] for item in response.grant_ids)
    assert root.subject_principal == child.subject_principal == "alice"
    assert root.actor_chain == ("support-orchestrator",)
    assert child.actor_chain == ("support-orchestrator", "case-service")
    assert child.parent_grant_id == root.grant_id
    assert child.operations <= root.operations and child.resources <= root.resources
    assert child.expires_at <= root.expires_at


def test_intermediate_case_boundary_authorizes_without_releasing_content() -> None:
    scenario = LAB.build_scenario()
    issued = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:no-early-release"), now=LAB.NOW
    )
    nonce = scenario.case_boundary.challenge("test:no-early-release")
    proof = scenario.proofs.issue(
        "attest:support", issued.grant, proof_id="proof:test:no-early-release", method="GET",
        uri="https://case-service.internal/resources/attachment:north:7", nonce=nonce, now=LAB.NOW,
    )
    admitted = scenario.case_boundary.authorize(
        "attest:support", issued.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="test:no-early-release", now=LAB.NOW,
    )
    assert admitted.status is LAB.DecisionStatus.ALLOW
    assert admitted.content is None


def test_cross_tenant_human_and_workload_cannot_be_combined() -> None:
    scenario = LAB.build_scenario()
    decision = scenario.grants.issue(
        "session:mallory", "attest:support",
        LAB.root_request("test:tenant", resources=frozenset({"attachment:south:9"})),
        now=LAB.NOW,
    )
    assert (decision.status, decision.reason, decision.grant) == (
        LAB.DecisionStatus.DENY, "tenant-binding", None
    )


def test_issuance_is_idempotent_but_request_id_collision_is_denied() -> None:
    scenario = LAB.build_scenario()
    original = LAB.root_request("test:idempotent")
    first = scenario.grants.issue("session:alice", "attest:support", original, now=LAB.NOW)
    retry = scenario.grants.issue("session:alice", "attest:support", original, now=LAB.NOW)
    collision = scenario.grants.issue(
        "session:alice", "attest:support",
        replace(original, resources=frozenset({"attachment:north:8"})), now=LAB.NOW,
    )
    assert retry.status is LAB.DecisionStatus.IDEMPOTENT
    assert retry.grant == first.grant
    assert (collision.status, collision.reason) == (LAB.DecisionStatus.DENY, "request-id-collision")


def test_grant_tampering_is_detected() -> None:
    scenario = LAB.build_scenario()
    issued = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:tamper"), now=LAB.NOW
    )
    tampered = replace(issued.grant, operations=frozenset({"delete"}))
    scenario.grants.grants[tampered.grant_id] = tampered
    current, reason = scenario.grants.validate_current(tampered, now=LAB.NOW)
    assert current is None and reason == "grant-integrity"


def test_exchange_can_only_attenuate_operation_resource_purpose_and_audience() -> None:
    scenario = LAB.build_scenario()
    parent = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:parent"), now=LAB.NOW
    )
    operation = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case",
        LAB.child_request("test:op", operations=frozenset({"read", "delete"})), now=LAB.NOW,
    )
    resource = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case",
        LAB.child_request("test:resource", resources=frozenset({"attachment:north:7", "attachment:north:8"})), now=LAB.NOW,
    )
    purpose = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case",
        LAB.child_request("test:purpose", purpose="bulk-export"), now=LAB.NOW,
    )
    audience = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case",
        LAB.child_request("test:audience", audience="unknown-service"), now=LAB.NOW,
    )
    assert [item.reason for item in (operation, resource, purpose, audience)] == [
        "operation-escalation", "resource-escalation", "purpose-escalation", "hop-not-allowed"
    ]


def test_sender_constrained_grant_rejects_a_stolen_bearer() -> None:
    scenario = LAB.build_scenario()
    issued = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:sender"), now=LAB.NOW
    )
    nonce = scenario.case_boundary.challenge("test:sender")
    proof = scenario.proofs.issue(
        "attest:stolen-host", issued.grant, proof_id="proof:test:sender", method="GET",
        uri="https://case-service.internal/resources/attachment:north:7", nonce=nonce, now=LAB.NOW,
    )
    decision = scenario.case_boundary.authorize(
        "attest:stolen-host", issued.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="test:sender", now=LAB.NOW,
    )
    assert (decision.status, decision.reason, decision.content) == (
        LAB.DecisionStatus.DENY, "sender", None
    )


def test_request_proof_is_bound_to_grant_method_uri_nonce_sender_and_one_use() -> None:
    scenario = LAB.build_scenario()
    issued = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:proof"), now=LAB.NOW
    )
    nonce = scenario.case_boundary.challenge("test:proof")
    proof = scenario.proofs.issue(
        "attest:support", issued.grant, proof_id="proof:test:proof", method="GET",
        uri="https://case-service.internal/resources/attachment:north:7", nonce=nonce, now=LAB.NOW,
    )
    first = scenario.case_boundary.authorize(
        "attest:support", issued.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="test:proof:first", now=LAB.NOW,
    )
    replay = scenario.case_boundary.authorize(
        "attest:support", issued.grant.grant_id, proof, operation="read",
        resource_id="attachment:north:7", request_id="test:proof:replay", now=LAB.NOW,
    )
    assert first.status is LAB.DecisionStatus.ALLOW
    assert (replay.status, replay.reason) == (LAB.DecisionStatus.DENY, "proof-replay")


def test_lineage_revocation_invalidates_parent_and_child() -> None:
    scenario = LAB.build_scenario()
    parent = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:revoke-parent"), now=LAB.NOW
    )
    child = scenario.grants.exchange(
        parent.grant.grant_id, "attest:case", LAB.child_request("test:revoke-child"), now=LAB.NOW
    )
    assert scenario.grants.revoke_lineage(parent.grant.grant_id, "incident") == 2
    assert scenario.grants.validate_current(parent.grant, now=LAB.NOW)[1] == "grant-revoked"
    assert scenario.grants.validate_current(child.grant, now=LAB.NOW)[1] == "grant-revoked"


def test_current_agent_and_entitlement_lifecycle_are_rechecked() -> None:
    scenario = LAB.build_scenario()
    issued = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:lifecycle"), now=LAB.NOW
    )
    entitlement = scenario.entitlements.snapshots["alice"]
    scenario.entitlements.snapshots["alice"] = replace(entitlement, version=5)
    assert scenario.grants.validate_current(issued.grant, now=LAB.NOW)[1] == "entitlement-version-changed"

    scenario = LAB.build_scenario()
    issued = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:disable"), now=LAB.NOW
    )
    agent = scenario.identities.agents["agent:support-7"]
    scenario.identities.agents[agent.agent_id] = replace(agent, lifecycle=LAB.Lifecycle.DISABLED)
    assert scenario.grants.validate_current(issued.grant, now=LAB.NOW)[1] == "agent-identity-disabled"


def test_expired_session_workload_and_grant_fail_closed() -> None:
    scenario = LAB.build_scenario()
    session = scenario.identities.sessions["session:alice"]
    scenario.identities.sessions[session.session_id] = replace(session, expires_at=LAB.NOW)
    decision = scenario.grants.issue(
        "session:alice", "attest:support", LAB.root_request("test:session-expired"), now=LAB.NOW
    )
    assert decision.reason == "session-expired"

    scenario = LAB.build_scenario()
    issued = scenario.grants.issue(
        "session:alice", "attest:support",
        LAB.root_request("test:grant-expired", ttl=timedelta(seconds=1)), now=LAB.NOW,
    )
    assert scenario.grants.validate_current(
        issued.grant, now=LAB.NOW + timedelta(seconds=1)
    )[1] == "grant-expired"


def test_failed_delegated_path_never_uses_ambient_service_authority() -> None:
    scenario = LAB.build_scenario()
    scenario.entitlements.available = False
    response = scenario.application.read_attachment(
        session_id="session:alice", agent_attestation_id="attest:support",
        attachment_id="attachment:north:7", request_id="test:no-fallback", now=LAB.NOW,
    )
    assert response.status is LAB.DecisionStatus.ERROR
    assert response.content is None
    assert scenario.application.ambient_fallback_count == 0


def test_receipts_are_attributable_and_do_not_copy_resource_content() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.read_attachment(
        session_id="session:alice", agent_attestation_id="attest:support",
        attachment_id="attachment:north:7", request_id="test:receipt", now=LAB.NOW,
    )
    for receipt in response.receipts:
        assert receipt.trace_id and receipt.policy_version and receipt.tenant_digest
        assert "Synthetic Northwind" not in repr(receipt)
        assert "alice" not in receipt.subject_digest
