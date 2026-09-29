"""Focused invariants for Intermediate 04 secrets and credential security."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "04-secrets-and-credential-security"
SPEC = importlib.util.spec_from_file_location("intermediate_04_credentials_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def issue_policy(scenario, request_id: str = "test:issue"):
    return scenario.broker.issue(
        "attest:support", LAB.policy_request(request_id), now=LAB.NOW
    )


def execute_policy(scenario, lease, request_id: str = "test:execute"):
    return scenario.policy_executor.execute(
        "attest:support", lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id=request_id, now=LAB.NOW,
    )


def test_declared_evaluation_separates_valid_attacks_exposure_and_failures() -> None:
    report, observations = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (18, 4, 12, 2)
    assert (report.credential_misuse_cases, report.exposure_cases) == (11, 1)
    assert report.valid_task_success_rate == report.trace_completeness_rate == 1.0
    assert report.failure_error_preservation_rate == 1.0
    assert report.credential_misuse_success_rate == 0.0
    assert report.secret_exposure_rate == 0.0
    assert report.replay_acceptance_rate == 0.0
    assert report.stale_credential_acceptance_rate == 0.0
    assert report.unsafe_baseline_exposure_rate == 1.0
    assert all(item.status == "error" for item in observations if item.kind is LAB.CaseKind.FAILURE)


def test_valid_application_path_materializes_only_inside_executor_and_zeroizes() -> None:
    scenario = LAB.build_scenario()
    issued = issue_policy(scenario)
    assert issued.status is LAB.DecisionStatus.ALLOW
    assert scenario.vault.materialization_count == 0
    decision = execute_policy(scenario, issued.lease)
    assert decision.status is LAB.DecisionStatus.ALLOW
    assert decision.content == "Synthetic Northwind policy summary"
    assert scenario.vault.materialization_count == 1
    assert scenario.policy_executor.last_handle_zeroized


def test_raw_material_never_enters_response_or_audit_receipts() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.read_policy(
        attestation_id="attest:support", policy_id="policy:north:7",
        request_id="test:no-exposure", now=LAB.NOW,
    )
    surface = {"response": response, "audit": scenario.audit.events}
    assert not LAB.contains_material(
        surface,
        (LAB._POLICY_MATERIAL_V1, LAB._POLICY_MATERIAL_V2, LAB._TICKET_MATERIAL_V1),
    )


def test_cross_tenant_issuance_is_denied_before_materialization() -> None:
    scenario = LAB.build_scenario()
    decision = scenario.broker.issue(
        "attest:south",
        LAB.policy_request("test:tenant", resource_id="policy:north:7"),
        now=LAB.NOW,
    )
    assert (decision.status, decision.reason, decision.lease) == (
        LAB.DecisionStatus.DENY, "resource-tenant", None
    )
    assert scenario.vault.materialization_count == 0


def test_lease_is_bound_to_exact_audience_operation_and_resource() -> None:
    scenario = LAB.build_scenario()
    lease = issue_policy(scenario, "test:bindings").lease
    audience = scenario.ticket_executor.execute(
        "attest:support", lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="test:audience", now=LAB.NOW,
    )
    operation = scenario.policy_executor.execute(
        "attest:support", lease.lease_id, operation="write_ticket",
        resource_id="policy:north:7", request_id="test:operation", now=LAB.NOW,
    )
    resource = scenario.policy_executor.execute(
        "attest:support", lease.lease_id, operation="read_policy",
        resource_id="policy:north:8", request_id="test:resource", now=LAB.NOW,
    )
    assert [item.reason for item in (audience, operation, resource)] == [
        "credential-audience", "credential-operation", "credential-resource"
    ]
    assert scenario.vault.materialization_count == 0


def test_stolen_lease_requires_named_workload_and_bound_key() -> None:
    scenario = LAB.build_scenario()
    lease = issue_policy(scenario, "test:sender").lease
    wrong_workload = scenario.policy_executor.execute(
        "attest:stolen", lease.lease_id, operation="read_policy",
        resource_id="policy:north:7", request_id="test:wrong-workload", now=LAB.NOW,
    )
    original = scenario.workloads.attestations["attest:support"]
    scenario.workloads.attestations["attest:support"] = replace(
        original, key_thumbprint="key:unbound"
    )
    wrong_key = execute_policy(scenario, lease, "test:wrong-key")
    assert wrong_workload.reason == "credential-sender"
    assert wrong_key.reason == "credential-sender-key"


def test_expiry_revocation_rotation_and_integrity_invalidate_a_lease() -> None:
    scenario = LAB.build_scenario()
    expired = scenario.broker.issue(
        "attest:support",
        LAB.policy_request("test:expired", ttl=timedelta(seconds=1)),
        now=LAB.NOW,
    ).lease
    assert scenario.broker.validate_current(
        expired, now=LAB.NOW + timedelta(seconds=1)
    )[1] == "credential-lease-expired"

    scenario = LAB.build_scenario()
    revoked = issue_policy(scenario, "test:revoked").lease
    assert scenario.broker.revoke(revoked.lease_id, "incident")
    assert scenario.broker.validate_current(revoked, now=LAB.NOW)[1] == "credential-lease-revoked"

    scenario = LAB.build_scenario()
    stale = issue_policy(scenario, "test:stale").lease
    scenario.rotate_policy_credential(now=LAB.NOW + timedelta(seconds=1))
    assert scenario.broker.validate_current(
        stale, now=LAB.NOW + timedelta(seconds=1)
    )[1] == "secret-version-changed"

    scenario = LAB.build_scenario()
    disabled = issue_policy(scenario, "test:disabled").lease
    scenario.vault.disable("secret:policy-api:north")
    assert scenario.broker.validate_current(disabled, now=LAB.NOW)[1] == "secret-disabled"

    scenario = LAB.build_scenario()
    original = issue_policy(scenario, "test:tamper").lease
    tampered = replace(original, audience="ticket-api")
    scenario.broker.leases[tampered.lease_id] = tampered
    assert scenario.broker.validate_current(tampered, now=LAB.NOW)[1] == "credential-lease-integrity"


def test_atomic_claim_allows_only_one_concurrent_dispatch() -> None:
    scenario = LAB.build_scenario()
    lease = issue_policy(scenario, "test:race").lease

    def invoke(index: int):
        return execute_policy(scenario, lease, f"test:race:{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(invoke, range(8)))
    assert sum(item.status is LAB.DecisionStatus.ALLOW for item in decisions) == 1
    assert sum(item.reason == "credential-lease-replayed" for item in decisions) == 7
    assert scenario.policy_provider.dispatch_count == 1
    assert scenario.vault.materialization_count == 1


def test_idempotent_issuance_rejects_request_id_collision() -> None:
    scenario = LAB.build_scenario()
    original = LAB.policy_request("test:idempotent")
    first = scenario.broker.issue("attest:support", original, now=LAB.NOW)
    retry = scenario.broker.issue("attest:support", original, now=LAB.NOW)
    collision = scenario.broker.issue(
        "attest:support", replace(original, resource_id="policy:north:8"), now=LAB.NOW
    )
    assert retry.status is LAB.DecisionStatus.IDEMPOTENT
    assert retry.lease == first.lease
    assert (collision.status, collision.reason) == (
        LAB.DecisionStatus.DENY, "request-id-collision"
    )


def test_provider_error_that_contains_material_is_redacted() -> None:
    scenario = LAB.build_scenario()
    scenario.policy_provider.leaking_error = True
    response = scenario.application.read_policy(
        attestation_id="attest:support", policy_id="policy:north:7",
        request_id="test:redaction", now=LAB.NOW,
    )
    assert (response.status, response.reason, response.content) == (
        LAB.DecisionStatus.ERROR, "provider-error-redacted", None
    )
    assert not LAB.contains_material(
        {"response": response, "audit": scenario.audit.events},
        (LAB._POLICY_MATERIAL_V1,),
    )


def test_dependency_failures_are_errors_without_ambient_fallback() -> None:
    for dependency in ("vault", "provider", "policy", "broker"):
        scenario = LAB.build_scenario()
        if dependency == "vault":
            scenario.vault.available = False
        elif dependency == "provider":
            scenario.policy_provider.available = False
        elif dependency == "policy":
            scenario.policy.available = False
        else:
            scenario.broker.available = False
        response = scenario.application.read_policy(
            attestation_id="attest:support", policy_id="policy:north:7",
            request_id=f"test:failure:{dependency}", now=LAB.NOW,
        )
        assert response.status is LAB.DecisionStatus.ERROR
        assert response.content is None
        assert scenario.application.ambient_fallback_count == 0


def test_ephemeral_handle_repr_is_redacted_and_buffer_is_zeroized() -> None:
    scenario = LAB.build_scenario()
    handle = scenario.vault.materialize("secret:policy-api:north", 1)
    assert repr(handle) == "<EphemeralSecret redacted>"
    with handle:
        assert bytes(handle.provider_view()).decode() == LAB._POLICY_MATERIAL_V1
    assert handle.zeroized
    assert set(bytes(handle._buffer)) == {0}
