"""Official Sigstore adapter tests for Advanced 06."""

import importlib.metadata
import importlib.util
import json
from pathlib import Path
import sys

from sigstore.dsse import Statement
from sigstore.verify.policy import Identity, UnsafeNoOp


COURSE = (
    Path(__file__).parents[1]
    / "curriculum/roadmap/advanced/06-agent-supply-chain-security"
)
SPEC = importlib.util.spec_from_file_location(
    "advanced_06_agent_supply_chain_sdk", COURSE / "sdk_adapter.py"
)
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_adapter_uses_supported_sigstore_sdk_line() -> None:
    assert importlib.metadata.version("sigstore").startswith("4.5.")


def test_official_statement_validates_in_toto_and_slsa_shape() -> None:
    candidate = SDK.core.candidate_for()
    context = SDK.build_sigstore_context(candidate)
    document = json.loads(context.statement_bytes)
    assert isinstance(context.statement, Statement)
    assert document["_type"] == SDK.core.IN_TOTO_STATEMENT_TYPE
    assert document["predicateType"] == SDK.core.SLSA_PROVENANCE_TYPE
    assert document["subject"][0]["digest"]["sha256"] == candidate.artifact.digest


def test_identity_policy_is_exact_and_never_unsafe_noop() -> None:
    candidate = SDK.core.candidate_for()
    context = SDK.build_sigstore_context(candidate)
    assert isinstance(context.identity_policy, Identity)
    assert not isinstance(context.identity_policy, UnsafeNoOp)
    assert context.identity_policy._identity == candidate.attestation.signer_identity
    assert context.identity_policy._issuer._value == candidate.attestation.signer_issuer


def test_slsa_predicate_preserves_builder_source_workflow_and_dependencies() -> None:
    candidate = SDK.core.candidate_for()
    document = SDK.statement_document(candidate)
    predicate = document["predicate"]
    definition = predicate["buildDefinition"]
    assert definition["buildType"] == candidate.attestation.statement.build_type
    assert definition["externalParameters"]["source"]["uri"] == candidate.attestation.statement.source_uri
    assert definition["internalParameters"]["workflowDigest"] == candidate.attestation.statement.workflow_digest
    assert len(definition["resolvedDependencies"]) == len(candidate.manifest.dependencies)
    assert predicate["runDetails"]["builder"]["id"] == candidate.attestation.statement.builder_id
    assert predicate["runDetails"]["metadata"]["startedOn"].endswith("Z")
    assert predicate["runDetails"]["metadata"]["finishedOn"].endswith("Z")


def test_sdk_schema_validation_precedes_application_release_and_staging() -> None:
    context, flow = SDK.verify_and_stage()
    assert isinstance(context.statement, Statement)
    assert flow.verification.reason == "candidate-verified"
    assert flow.canary.reason == "canary-authorized"
    assert flow.promotion.reason == "promotion-authorized"
    assert flow.promotion.deployment.stage is SDK.core.DeploymentStage.PRODUCTION


def test_credential_free_demo_makes_no_network_oidc_or_model_calls() -> None:
    proof = SDK.credential_free_demo()
    assert proof["slsa_version"] == "1.2"
    assert proof["subject_digest"] == proof["artifact_digest"]
    assert proof["stage"] == "production"
    assert proof["network_calls"] == 0
    assert proof["oidc_credentials"] == 0
    assert proof["model_calls"] == 0
