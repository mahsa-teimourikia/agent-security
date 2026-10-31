"""Invariant tests for Advanced 06 agent supply-chain security."""

from dataclasses import asdict, replace
import base64
import importlib.util
import json
from pathlib import Path
import sys

import pytest


COURSE = (
    Path(__file__).parents[1]
    / "curriculum/roadmap/advanced/06-agent-supply-chain-security"
)
SPEC = importlib.util.spec_from_file_location(
    "advanced_06_agent_supply_chain_lab", COURSE / "lab.py"
)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def scenario(kind=LAB.ComponentKind.MCP_SERVER, candidate_id="test:candidate:1"):
    gate, principals, candidates = LAB.build_scenario()
    candidate = replace(candidates[kind], candidate_id=candidate_id)
    return gate, principals, candidate


def verify(kind=LAB.ComponentKind.MCP_SERVER, candidate_id="test:candidate:1"):
    gate, principals, candidate = scenario(kind, candidate_id)
    decision = gate.verify_candidate(
        principals["verifier"], candidate, now=LAB.NOW, step=0
    )
    return gate, principals, candidate, decision


def promoted(kind=LAB.ComponentKind.MCP_SERVER, suffix="test"):
    return LAB.run_valid_release(kind, suffix=suffix)


def resign(candidate, **changes):
    statement = replace(candidate.attestation.statement, **changes)
    return LAB.resign(candidate, statement)


def test_unsafe_baseline_exposes_supply_chain_failures() -> None:
    baseline = LAB.unsafe_supply_chain_baseline()
    assert baseline.verified_artifact_coverage == 0.2
    assert baseline.unpinned_component_rate == pytest.approx(2 / 3)
    assert baseline.provenance_failure_detection_rate == 0.0
    assert baseline.forbidden_release_rate == 1.0
    assert baseline.median_rollback_seconds == 1050.0


@pytest.mark.parametrize("kind", list(LAB.ComponentKind))
def test_every_component_kind_completes_verified_staged_release(kind) -> None:
    flow = promoted(kind, suffix=f"valid-{kind.value}")
    verified = flow.verification.verified
    deployment = flow.promotion.deployment
    assert verified and deployment
    assert verified.artifact_digest == deployment.artifact_digest
    assert deployment.stage is LAB.DeploymentStage.PRODUCTION
    assert flow.gate.current_digests[verified.component_id] == verified.artifact_digest


def test_real_signature_is_verified_over_exact_statement() -> None:
    _, _, candidate, decision = verify()
    assert decision.allowed and decision.verified
    assert decision.verified.signer_identity == candidate.attestation.signer_identity
    assert decision.verified.source_commit == candidate.attestation.statement.source_commit


@pytest.mark.parametrize(
    ("principal_change", "reason"),
    [
        ({"authenticated": False}, "principal-unauthenticated"),
        ({"tenant": "south"}, "principal-tenant"),
        ({"roles": frozenset()}, "principal-role"),
    ],
)
def test_verification_requires_authenticated_authorized_tenant_principal(
    principal_change, reason
) -> None:
    gate, principals, candidate = scenario(candidate_id=f"test:{reason}")
    principal = replace(principals["verifier"], **principal_change)
    decision = gate.verify_candidate(principal, candidate, now=LAB.NOW, step=0)
    assert not decision.allowed and decision.reason == reason


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda item: replace(
                item,
                manifest=replace(item.manifest, artifact_ref="registry.example/mcp:latest"),
            ),
            "artifact-reference",
        ),
        (
            lambda item: replace(
                item,
                artifact=replace(item.artifact, content=b"substituted"),
            ),
            "artifact-digest",
        ),
        (
            lambda item: replace(
                item,
                manifest=replace(
                    item.manifest,
                    capabilities=item.manifest.capabilities | {"records.export"},
                ),
            ),
            "capability-widening",
        ),
        (
            lambda item: replace(
                item,
                manifest=replace(
                    item.manifest,
                    dependencies=(
                        replace(item.manifest.dependencies[0], uri="runtime:latest"),
                        item.manifest.dependencies[1],
                    ),
                ),
            ),
            "dependency-reference",
        ),
    ],
)
def test_artifact_manifest_and_dependencies_are_immutable_and_least_privilege(
    mutation, reason
) -> None:
    gate, principals, candidate = scenario(candidate_id=f"test:{reason}")
    decision = gate.verify_candidate(
        principals["verifier"], mutation(candidate), now=LAB.NOW, step=0
    )
    assert not decision.allowed and decision.reason == reason


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda item: resign(item, statement_type="https://attacker/Statement/v1"),
            "attestation-statement-type",
        ),
        (
            lambda item: resign(item, predicate_type="https://attacker/predicate"),
            "attestation-predicate-type",
        ),
        (
            lambda item: resign(item, subject_digest="0" * 64),
            "attestation-subject",
        ),
        (
            lambda item: resign(item, builder_id="https://runner.attacker"),
            "attestation-builder",
        ),
        (
            lambda item: resign(item, source_uri="git+https://github.com/attacker/repo"),
            "attestation-source",
        ),
        (
            lambda item: resign(item, source_commit="refs/heads/main"),
            "attestation-source",
        ),
        (
            lambda item: resign(item, workflow_digest="0" * 64),
            "attestation-workflow",
        ),
        (
            lambda item: resign(item, tenant="south"),
            "attestation-scope",
        ),
        (
            lambda item: resign(item, issued_at=LAB.NOW - 7200, expires_at=LAB.NOW + 10),
            "attestation-lifecycle",
        ),
        (
            lambda item: resign(item, resolved_dependencies=()),
            "attestation-materials",
        ),
    ],
)
def test_provenance_fields_are_policy_checked_after_signature_validation(
    mutation, reason
) -> None:
    gate, principals, candidate = scenario(candidate_id=f"test:{reason}")
    decision = gate.verify_candidate(
        principals["verifier"], mutation(candidate), now=LAB.NOW, step=0
    )
    assert not decision.allowed and decision.reason == reason


def test_signer_identity_issuer_and_signature_are_independent_checks() -> None:
    gate, principals, candidate = scenario(candidate_id="test:identity")
    wrong_identity = LAB.resign(
        candidate,
        candidate.attestation.statement,
        signer_identity="https://github.com/attacker/release.yml",
    )
    identity = gate.verify_candidate(
        principals["verifier"], wrong_identity, now=LAB.NOW, step=0
    )
    assert identity.reason == "attestation-identity"

    gate, principals, candidate = scenario(candidate_id="test:issuer")
    wrong_issuer = LAB.resign(
        candidate,
        candidate.attestation.statement,
        signer_issuer="https://attacker.example/oidc",
    )
    issuer = gate.verify_candidate(
        principals["verifier"], wrong_issuer, now=LAB.NOW, step=0
    )
    assert issuer.reason == "attestation-identity"

    gate, principals, candidate = scenario(candidate_id="test:signature")
    forged = replace(
        candidate,
        attestation=replace(
            candidate.attestation,
            signature=base64.b64encode(b"0" * 64).decode(),
        ),
    )
    signature = gate.verify_candidate(
        principals["verifier"], forged, now=LAB.NOW, step=0
    )
    assert signature.reason == "attestation-signature"


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda item: replace(
                item,
                inventory=replace(item.inventory, subject_digest="0" * 64),
            ),
            "inventory-subject",
        ),
        (
            lambda item: replace(
                item,
                inventory=replace(item.inventory, format_version="1.6"),
            ),
            "inventory-format",
        ),
        (
            lambda item: replace(
                item,
                inventory=replace(item.inventory, complete=False, components=()),
            ),
            "inventory-completeness",
        ),
        (
            lambda item: replace(
                item, scan=replace(item.scan, subject_digest="0" * 64)
            ),
            "scan-subject",
        ),
        (
            lambda item: replace(
                item, scan=replace(item.scan, critical_findings=1)
            ),
            "risk-threshold",
        ),
    ],
)
def test_inventory_and_scan_evidence_are_bound_and_policy_checked(
    mutation, reason
) -> None:
    gate, principals, candidate = scenario(candidate_id=f"test:{reason}")
    decision = gate.verify_candidate(
        principals["verifier"], mutation(candidate), now=LAB.NOW, step=0
    )
    assert not decision.allowed and decision.reason == reason


def test_revoked_digest_is_rejected_before_rollout() -> None:
    gate, principals, candidate = scenario(candidate_id="test:revoked")
    gate.revoked_digests.add(candidate.artifact.digest)
    decision = gate.verify_candidate(
        principals["verifier"], candidate, now=LAB.NOW, step=0
    )
    assert decision.reason == "artifact-revoked"


def test_candidate_retry_is_exactly_idempotent_and_mutation_is_denied() -> None:
    gate, principals, candidate = scenario(candidate_id="test:retry")
    first = gate.verify_candidate(
        principals["verifier"], candidate, now=LAB.NOW, step=0
    )
    retry = gate.verify_candidate(
        principals["verifier"], candidate, now=LAB.NOW, step=1
    )
    mutation = gate.verify_candidate(
        principals["verifier"],
        replace(candidate, scan=replace(candidate.scan, high_findings=2)),
        now=LAB.NOW,
        step=2,
    )
    assert first.allowed and retry.allowed and retry.replayed
    assert retry.verified == first.verified
    assert mutation.reason == "candidate-replay-mismatch"


def test_canary_requires_verified_release_and_authorized_deployer() -> None:
    gate, principals, _, verification = verify(candidate_id="test:canary")
    missing = gate.start_canary(
        principals["deployer"], "verification:missing", "deployment:missing",
        now=LAB.NOW + 1, step=1,
    )
    wrong_role = gate.start_canary(
        principals["verifier"], verification.verified.verification_id,
        "deployment:wrong-role", now=LAB.NOW + 1, step=2,
    )
    assert missing.reason == "verification-missing"
    assert wrong_role.reason == "deployer-role"


def test_canary_retry_is_exact_and_deployment_id_mutation_is_denied() -> None:
    gate, principals, _, verification = verify(candidate_id="test:canary:retry")
    first = gate.start_canary(
        principals["deployer"], verification.verified.verification_id,
        "deployment:retry", now=LAB.NOW + 1, step=1,
    )
    retry = gate.start_canary(
        principals["deployer"], verification.verified.verification_id,
        "deployment:retry", now=LAB.NOW + 2, step=2,
    )
    mutated = gate.start_canary(
        principals["deployer"], "verification:other",
        "deployment:retry", now=LAB.NOW + 3, step=3,
    )
    assert first.allowed and retry.allowed and retry.replayed
    assert mutated.reason == "deployment-replay-mismatch"


@pytest.mark.parametrize(
    ("observation_change", "reason", "expected_state"),
    [
        ({"artifact_digest": "0" * 64}, "observation-binding", LAB.DecisionState.DENY),
        ({"sample_count": 99}, "canary-insufficient-samples", LAB.DecisionState.STOP),
        ({"error_rate": 0.02}, "canary-threshold", LAB.DecisionState.STOP),
        ({"forbidden_action_count": 1}, "canary-threshold", LAB.DecisionState.STOP),
        ({"provenance_failure_count": 1}, "canary-threshold", LAB.DecisionState.STOP),
    ],
)
def test_promotion_is_bound_to_healthy_sufficient_canary_evidence(
    observation_change, reason, expected_state
) -> None:
    gate, principals, _, verification = verify(candidate_id=f"test:promotion:{reason}")
    canary = gate.start_canary(
        principals["deployer"], verification.verified.verification_id,
        f"deployment:{reason}", now=LAB.NOW + 1, step=1,
    )
    observation = replace(
        LAB.healthy_observation(canary.deployment, suffix=reason),
        **observation_change,
    )
    decision = gate.promote(
        principals["deployer"],
        LAB.PromotionProposal(
            f"promotion:{reason}", canary.deployment.deployment_id,
            verification.verified.verification_id, "north", "production",
            observation,
        ),
        now=LAB.NOW + 12, step=2,
    )
    assert decision.state is expected_state and decision.reason == reason


def test_promotion_retry_is_exact_and_does_not_duplicate_activation() -> None:
    gate, principals, _, verification = verify(candidate_id="test:promotion:retry")
    canary = gate.start_canary(
        principals["deployer"], verification.verified.verification_id,
        "deployment:promotion:retry", now=LAB.NOW + 1, step=1,
    )
    proposal = LAB.PromotionProposal(
        "promotion:retry", canary.deployment.deployment_id,
        verification.verified.verification_id, "north", "production",
        LAB.healthy_observation(canary.deployment, suffix="retry"),
    )
    first = gate.promote(
        principals["deployer"], proposal, now=LAB.NOW + 12, step=2
    )
    retry = gate.promote(
        principals["deployer"], proposal, now=LAB.NOW + 13, step=3
    )
    mutation = gate.promote(
        principals["deployer"],
        replace(proposal, environment="staging"),
        now=LAB.NOW + 14, step=4,
    )
    assert first.allowed and retry.allowed and retry.replayed
    assert retry.deployment == first.deployment
    assert mutation.reason == "promotion-replay-mismatch"


def test_one_use_rollback_restores_last_known_good_digest() -> None:
    flow = promoted(suffix="rollback")
    deployment = flow.promotion.deployment
    issued = flow.gate.issue_rollback_guard(
        flow.principals["monitor"], deployment.deployment_id,
        "incident:rollback", "guard:rollback", now=LAB.NOW + 20, step=3,
    )
    result = flow.gate.consume_rollback(
        flow.principals["deployer"], issued.rollback_guard.guard_id,
        now=LAB.NOW + 32, step=4,
    )
    replay = flow.gate.consume_rollback(
        flow.principals["deployer"], issued.rollback_guard.guard_id,
        now=LAB.NOW + 33, step=5,
    )
    assert result.allowed and result.rollback.duration_seconds == 12
    assert result.rollback.restored_digest == deployment.previous_digest
    assert flow.gate.current_digests[deployment.component_id] == deployment.previous_digest
    assert replay.reason == "rollback-guard-consumed"


def test_expired_or_wrong_role_rollback_guard_cannot_restore() -> None:
    flow = promoted(suffix="rollback-deny")
    deployment = flow.promotion.deployment
    issued = flow.gate.issue_rollback_guard(
        flow.principals["monitor"], deployment.deployment_id,
        "incident:deny", "guard:deny", now=LAB.NOW + 20, ttl=5, step=3,
    )
    wrong_role = flow.gate.consume_rollback(
        flow.principals["verifier"], issued.rollback_guard.guard_id,
        now=LAB.NOW + 21, step=4,
    )
    expired = flow.gate.consume_rollback(
        flow.principals["deployer"], issued.rollback_guard.guard_id,
        now=LAB.NOW + 25, step=5,
    )
    assert wrong_role.reason == "rollback-executor-role"
    assert expired.reason == "rollback-guard-expired"


@pytest.mark.parametrize(
    ("dependency", "reason"),
    [
        ("trust_store_available", "trust-store-unavailable"),
        ("policy_store_available", "policy-store-unavailable"),
        ("verifier_available", "signature-verifier-unavailable"),
        ("inventory_service_available", "inventory-service-unavailable"),
    ],
)
def test_verification_dependencies_fail_as_explicit_errors(
    dependency, reason
) -> None:
    gate, principals, candidate = scenario(candidate_id=f"test:failure:{dependency}")
    setattr(gate, dependency, False)
    decision = gate.verify_candidate(
        principals["verifier"], candidate, now=LAB.NOW, step=0
    )
    assert decision.state is LAB.DecisionState.ERROR
    assert decision.reason == reason


def test_rollout_dependency_failure_never_falls_back_to_activation() -> None:
    gate, principals, _, verification = verify(candidate_id="test:rollout:failure")
    gate.rollout_store_available = False
    canary = gate.start_canary(
        principals["deployer"], verification.verified.verification_id,
        "deployment:failure", now=LAB.NOW + 1, step=1,
    )
    assert canary.state is LAB.DecisionState.ERROR
    assert canary.reason == "rollout-store-unavailable"
    assert verification.verified.component_id not in {
        key for key, value in gate.current_digests.items()
        if value == verification.verified.artifact_digest
    }


def test_receipts_exclude_artifact_content_and_signature_material() -> None:
    gate, _, candidate, decision = verify(candidate_id="test:receipt")
    serialized = json.dumps([asdict(receipt) for receipt in gate.receipts], default=str)
    assert candidate.artifact.content.decode() not in serialized
    assert candidate.attestation.signature not in serialized
    assert decision.receipt.artifact_digest == candidate.artifact.digest
    assert decision.receipt.policy_version == LAB.POLICY_VERSION


def test_evaluation_population_and_metric_semantics_are_exact() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.total_cases, report.valid_cases, report.attack_cases,
            report.failure_cases, report.recovery_cases) == (24, 5, 14, 3, 2)
    assert {case.category for case in cases} == {
        "valid", "attack", "failure", "recovery"
    }
    assert report.valid_deployment_completion_rate == 1.0
    assert report.verified_artifact_coverage == 1.0
    assert report.unpinned_component_rate == 0.0
    assert report.provenance_failures == 9
    assert report.provenance_failure_detection_rate == 1.0
    assert report.forbidden_release_rate == 0.0
    assert report.failure_error_rate == 1.0
    assert report.rollback_success_rate == 1.0
    assert report.median_rollback_seconds == 13.0
    assert report.maximum_rollback_seconds == 14
    assert report.audit_coverage_rate == 1.0
    assert report.unsafe_baseline_forbidden_release_rate == 1.0
