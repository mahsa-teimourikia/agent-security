"""Deterministic release gate for Advanced 06 agent supply-chain security.

The lab verifies synthetic artifacts with real Ed25519 signatures and explicit
policy. It does not claim that its local key registry, in-memory state, or
logical clock is a production transparency service, deployment controller, or
key-management system.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import base64
import hashlib
import json
from statistics import median
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


NOW = 2_000_000_000
POLICY_VERSION = "agent-supply-chain-policy-1"
SLSA_VERSION = "1.2"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"


def _normal(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, bytes):
        return {"sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, (set, frozenset)):
        return sorted(_normal(item) for item in value)
    if isinstance(value, tuple):
        return [_normal(item) for item in value]
    if isinstance(value, list):
        return [_normal(item) for item in value]
    if isinstance(value, dict):
        return {
            str(key): _normal(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if hasattr(value, "__dataclass_fields__"):
        return _normal(asdict(value))
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(
        _normal(value), sort_keys=True, separators=(",", ":")
    ).encode()


def _digest(value: bytes | str | object) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode()
    else:
        payload = _canonical(value)
    return hashlib.sha256(payload).hexdigest()


def _private_key(seed: str) -> Ed25519PrivateKey:
    """Return a deterministic teaching key; production keys belong in KMS/HSM."""

    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed.encode()).digest())


class DecisionState(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"
    STOP = "stop"


class ComponentKind(str, Enum):
    PROMPT_BUNDLE = "prompt-bundle"
    POLICY_BUNDLE = "policy-bundle"
    PLUGIN = "plugin"
    MCP_SERVER = "mcp-server"
    MODEL_ADAPTER = "model-adapter"


class DeploymentStage(str, Enum):
    CANARY = "canary"
    PRODUCTION = "production"
    ROLLED_BACK = "rolled-back"


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class Artifact:
    name: str
    kind: ComponentKind
    content: bytes

    @property
    def digest(self) -> str:
        return _digest(self.content)


@dataclass(frozen=True)
class ArtifactReference:
    name: str
    uri: str
    sha256: str


@dataclass(frozen=True)
class ComponentManifest:
    component_id: str
    kind: ComponentKind
    version: str
    artifact_ref: str
    artifact_digest: str
    tenant: str
    environment: str
    capabilities: frozenset[str]
    dependencies: tuple[ArtifactReference, ...]


@dataclass(frozen=True)
class ProvenanceStatement:
    statement_type: str
    predicate_type: str
    subject_name: str
    subject_digest: str
    builder_id: str
    build_type: str
    source_uri: str
    source_commit: str
    workflow_digest: str
    resolved_dependencies: tuple[ArtifactReference, ...]
    tenant: str
    environment: str
    issued_at: int
    expires_at: int


@dataclass(frozen=True)
class SignedAttestation:
    signer_identity: str
    signer_issuer: str
    statement: ProvenanceStatement
    signature: str


@dataclass(frozen=True)
class Inventory:
    inventory_id: str
    subject_digest: str
    format_name: str
    format_version: str
    complete: bool
    components: tuple[ArtifactReference, ...]
    generated_at: int


@dataclass(frozen=True)
class ScanEvidence:
    scan_id: str
    subject_digest: str
    scanner: str
    scanner_version: str
    critical_findings: int
    high_findings: int
    generated_at: int


@dataclass(frozen=True)
class ReleaseCandidate:
    candidate_id: str
    artifact: Artifact
    manifest: ComponentManifest
    attestation: SignedAttestation
    inventory: Inventory
    scan: ScanEvidence


@dataclass(frozen=True)
class ReleasePolicy:
    component_id: str
    kind: ComponentKind
    tenant: str
    environment: str
    allowed_capabilities: frozenset[str]
    source_uri: str
    approved_source_commits: frozenset[str]
    builder_id: str
    build_type: str
    workflow_digest: str
    signer_identity: str
    signer_issuer: str
    max_attestation_age: int = 3600
    max_scan_age: int = 3600
    max_critical_findings: int = 0
    max_high_findings: int = 2


@dataclass(frozen=True)
class VerificationReceipt:
    receipt_id: str
    stage: str
    state: DecisionState
    reason: str
    candidate_id: str
    component_id: str
    artifact_digest: str
    actor: str
    tenant: str
    environment: str
    signer_identity: str
    builder_id: str
    policy_version: str
    parent_receipt_id: str
    step: int


@dataclass(frozen=True)
class VerifiedRelease:
    verification_id: str
    candidate_id: str
    component_id: str
    kind: ComponentKind
    artifact_digest: str
    tenant: str
    environment: str
    capabilities: frozenset[str]
    signer_identity: str
    builder_id: str
    source_uri: str
    source_commit: str
    inventory_id: str
    scan_id: str
    receipt_id: str
    policy_version: str


@dataclass(frozen=True)
class CanaryObservation:
    observation_id: str
    deployment_id: str
    artifact_digest: str
    sample_count: int
    error_rate: float
    forbidden_action_count: int
    provenance_failure_count: int
    started_at: int
    ended_at: int


@dataclass(frozen=True)
class Deployment:
    deployment_id: str
    verification_id: str
    component_id: str
    artifact_digest: str
    previous_digest: str
    tenant: str
    environment: str
    stage: DeploymentStage
    receipt_id: str
    started_at: int


@dataclass(frozen=True)
class PromotionProposal:
    promotion_id: str
    deployment_id: str
    verification_id: str
    tenant: str
    environment: str
    observation: CanaryObservation


@dataclass(frozen=True)
class RollbackGuard:
    guard_id: str
    deployment_id: str
    component_id: str
    failed_digest: str
    target_digest: str
    incident_id: str
    tenant: str
    environment: str
    issued_at: int
    expires_at: int
    consumed: bool = False


@dataclass(frozen=True)
class RollbackResult:
    guard_id: str
    deployment_id: str
    restored_digest: str
    incident_id: str
    duration_seconds: int
    receipt_id: str


@dataclass(frozen=True)
class Decision:
    state: DecisionState
    reason: str
    receipt: VerificationReceipt
    verified: VerifiedRelease | None = None
    deployment: Deployment | None = None
    rollback_guard: RollbackGuard | None = None
    rollback: RollbackResult | None = None
    replayed: bool = False

    @property
    def allowed(self) -> bool:
        return self.state is DecisionState.ALLOW


@dataclass(frozen=True)
class ReleaseFlow:
    gate: "SupplyChainReleaseGate"
    principals: dict[str, Principal]
    verification: Decision
    canary: Decision
    promotion: Decision


@dataclass(frozen=True)
class ControlCase:
    case_id: str
    category: str
    state: DecisionState
    reason: str
    unauthorized_release: bool
    receipt_present: bool
    provenance_attack: bool = False
    rollback_seconds: int | None = None


@dataclass(frozen=True)
class EvaluationReport:
    total_cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    recovery_cases: int
    valid_deployment_completion_rate: float
    verified_artifact_coverage: float
    unpinned_component_rate: float
    provenance_failures: int
    provenance_failure_detection_rate: float
    forbidden_release_rate: float
    failure_error_rate: float
    rollback_success_rate: float
    median_rollback_seconds: float
    maximum_rollback_seconds: int
    audit_coverage_rate: float
    unsafe_baseline_forbidden_release_rate: float


@dataclass(frozen=True)
class UnsafeBaseline:
    release_candidates: int
    cryptographically_verified: int
    referenced_components: int
    pinned_components: int
    provenance_attack_cases: int
    detected_provenance_failures: int
    attack_cases: int
    forbidden_releases: int
    rollback_seconds: tuple[int, ...]

    @property
    def verified_artifact_coverage(self) -> float:
        return self.cryptographically_verified / self.release_candidates

    @property
    def unpinned_component_rate(self) -> float:
        return 1 - self.pinned_components / self.referenced_components

    @property
    def provenance_failure_detection_rate(self) -> float:
        return self.detected_provenance_failures / self.provenance_attack_cases

    @property
    def forbidden_release_rate(self) -> float:
        return self.forbidden_releases / self.attack_cases

    @property
    def median_rollback_seconds(self) -> float:
        return float(median(self.rollback_seconds))


class SupplyChainReleaseGate:
    """Application-owned verification, rollout, and recovery boundary."""

    def __init__(
        self,
        policies: Mapping[ComponentKind, ReleasePolicy],
        trusted_signers: Mapping[tuple[str, str], bytes],
        previous_digests: Mapping[str, str],
    ) -> None:
        self.policies = dict(policies)
        self.trusted_signers = dict(trusted_signers)
        self.current_digests = dict(previous_digests)
        self.revoked_digests: set[str] = set()
        self.receipts: list[VerificationReceipt] = []
        self.verified: dict[str, VerifiedRelease] = {}
        self.deployments: dict[str, Deployment] = {}
        self.rollback_guards: dict[str, RollbackGuard] = {}
        self.candidate_index: dict[str, str] = {}
        self.candidate_results: dict[str, Decision] = {}
        self.deployment_index: dict[str, str] = {}
        self.promotion_index: dict[str, str] = {}
        self.promotion_results: dict[str, Decision] = {}
        self.guard_index: dict[str, str] = {}
        self.trust_store_available = True
        self.policy_store_available = True
        self.verifier_available = True
        self.inventory_service_available = True
        self.rollout_store_available = True

    def _record(
        self,
        *,
        stage: str,
        state: DecisionState,
        reason: str,
        step: int,
        actor: str = "",
        candidate: ReleaseCandidate | None = None,
        component_id: str = "",
        digest: str = "",
        tenant: str = "",
        environment: str = "",
        signer_identity: str = "",
        builder_id: str = "",
        parent_receipt_id: str = "",
    ) -> VerificationReceipt:
        if candidate:
            component_id = candidate.manifest.component_id
            digest = candidate.artifact.digest
            tenant = candidate.manifest.tenant
            environment = candidate.manifest.environment
            signer_identity = candidate.attestation.signer_identity
            builder_id = candidate.attestation.statement.builder_id
            candidate_id = candidate.candidate_id
        else:
            candidate_id = ""
        receipt = VerificationReceipt(
            receipt_id=f"receipt:{len(self.receipts) + 1:04d}",
            stage=stage,
            state=state,
            reason=reason,
            candidate_id=candidate_id,
            component_id=component_id,
            artifact_digest=digest,
            actor=actor,
            tenant=tenant,
            environment=environment,
            signer_identity=signer_identity,
            builder_id=builder_id,
            policy_version=POLICY_VERSION,
            parent_receipt_id=parent_receipt_id,
            step=step,
        )
        self.receipts.append(receipt)
        return receipt

    @staticmethod
    def _is_digest_ref(value: str, digest: str | None = None) -> bool:
        if not value.startswith("sha256:") or len(value) != 71:
            return False
        encoded = value.removeprefix("sha256:")
        if any(character not in "0123456789abcdef" for character in encoded):
            return False
        return digest is None or encoded == digest

    def verify_candidate(
        self,
        principal: Principal,
        candidate: ReleaseCandidate,
        *,
        now: int,
        step: int,
    ) -> Decision:
        fingerprint = _digest(candidate)
        prior = self.candidate_index.get(candidate.candidate_id)
        if prior:
            if prior == fingerprint:
                previous = self.candidate_results[candidate.candidate_id]
                return replace(previous, replayed=True)
            receipt = self._record(
                stage="verify",
                state=DecisionState.DENY,
                reason="candidate-replay-mismatch",
                step=step,
                actor=principal.subject,
                candidate=candidate,
            )
            return Decision(DecisionState.DENY, receipt.reason, receipt)

        state, reason = DecisionState.ALLOW, "candidate-verified"
        rule = self.policies.get(candidate.manifest.kind)
        statement = candidate.attestation.statement
        actual_digest = candidate.artifact.digest

        if not self.trust_store_available:
            state, reason = DecisionState.ERROR, "trust-store-unavailable"
        elif not self.policy_store_available:
            state, reason = DecisionState.ERROR, "policy-store-unavailable"
        elif not self.verifier_available:
            state, reason = DecisionState.ERROR, "signature-verifier-unavailable"
        elif not self.inventory_service_available:
            state, reason = DecisionState.ERROR, "inventory-service-unavailable"
        elif not principal.authenticated:
            state, reason = DecisionState.DENY, "principal-unauthenticated"
        elif principal.tenant != candidate.manifest.tenant:
            state, reason = DecisionState.DENY, "principal-tenant"
        elif "release.verify" not in principal.roles:
            state, reason = DecisionState.DENY, "principal-role"
        elif not rule or rule.component_id != candidate.manifest.component_id:
            state, reason = DecisionState.DENY, "policy-component"
        elif candidate.artifact.kind is not candidate.manifest.kind:
            state, reason = DecisionState.DENY, "artifact-kind"
        elif candidate.manifest.artifact_digest != actual_digest:
            state, reason = DecisionState.DENY, "artifact-digest"
        elif not self._is_digest_ref(candidate.manifest.artifact_ref, actual_digest):
            state, reason = DecisionState.DENY, "artifact-reference"
        elif actual_digest in self.revoked_digests:
            state, reason = DecisionState.DENY, "artifact-revoked"
        elif any(
            not self._is_digest_ref(dependency.uri, dependency.sha256)
            for dependency in candidate.manifest.dependencies
        ):
            state, reason = DecisionState.DENY, "dependency-reference"
        elif candidate.manifest.tenant != rule.tenant or candidate.manifest.environment != rule.environment:
            state, reason = DecisionState.DENY, "manifest-scope"
        elif not candidate.manifest.capabilities.issubset(rule.allowed_capabilities):
            state, reason = DecisionState.DENY, "capability-widening"
        elif statement.statement_type != IN_TOTO_STATEMENT_TYPE:
            state, reason = DecisionState.DENY, "attestation-statement-type"
        elif statement.predicate_type != SLSA_PROVENANCE_TYPE:
            state, reason = DecisionState.DENY, "attestation-predicate-type"
        elif statement.subject_name != candidate.artifact.name or statement.subject_digest != actual_digest:
            state, reason = DecisionState.DENY, "attestation-subject"
        elif candidate.attestation.signer_identity != rule.signer_identity or candidate.attestation.signer_issuer != rule.signer_issuer:
            state, reason = DecisionState.DENY, "attestation-identity"
        elif statement.builder_id != rule.builder_id or statement.build_type != rule.build_type:
            state, reason = DecisionState.DENY, "attestation-builder"
        elif statement.source_uri != rule.source_uri or statement.source_commit not in rule.approved_source_commits:
            state, reason = DecisionState.DENY, "attestation-source"
        elif statement.workflow_digest != rule.workflow_digest:
            state, reason = DecisionState.DENY, "attestation-workflow"
        elif statement.tenant != rule.tenant or statement.environment != rule.environment:
            state, reason = DecisionState.DENY, "attestation-scope"
        elif statement.issued_at > now or statement.expires_at <= now or now - statement.issued_at > rule.max_attestation_age:
            state, reason = DecisionState.DENY, "attestation-lifecycle"
        elif statement.resolved_dependencies != candidate.manifest.dependencies:
            state, reason = DecisionState.DENY, "attestation-materials"
        else:
            public_bytes = self.trusted_signers.get(
                (
                    candidate.attestation.signer_identity,
                    candidate.attestation.signer_issuer,
                )
            )
            if not public_bytes:
                state, reason = DecisionState.DENY, "attestation-key"
            else:
                try:
                    signature = base64.b64decode(
                        candidate.attestation.signature, validate=True
                    )
                    Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                        signature, _canonical(statement)
                    )
                except (InvalidSignature, ValueError):
                    state, reason = DecisionState.DENY, "attestation-signature"

        if state is DecisionState.ALLOW:
            inventory_refs = {
                (item.name, item.uri, item.sha256)
                for item in candidate.inventory.components
            }
            manifest_refs = {
                (item.name, item.uri, item.sha256)
                for item in candidate.manifest.dependencies
            }
            if candidate.inventory.subject_digest != actual_digest:
                state, reason = DecisionState.DENY, "inventory-subject"
            elif candidate.inventory.format_name != "CycloneDX" or candidate.inventory.format_version != "1.7":
                state, reason = DecisionState.DENY, "inventory-format"
            elif not candidate.inventory.complete or inventory_refs != manifest_refs:
                state, reason = DecisionState.DENY, "inventory-completeness"
            elif candidate.inventory.generated_at > now or now - candidate.inventory.generated_at > rule.max_scan_age:
                state, reason = DecisionState.DENY, "inventory-lifecycle"
            elif candidate.scan.subject_digest != actual_digest:
                state, reason = DecisionState.DENY, "scan-subject"
            elif candidate.scan.generated_at > now or now - candidate.scan.generated_at > rule.max_scan_age:
                state, reason = DecisionState.DENY, "scan-lifecycle"
            elif candidate.scan.critical_findings > rule.max_critical_findings or candidate.scan.high_findings > rule.max_high_findings:
                state, reason = DecisionState.DENY, "risk-threshold"

        receipt = self._record(
            stage="verify",
            state=state,
            reason=reason,
            step=step,
            actor=principal.subject,
            candidate=candidate,
        )
        verified = None
        if state is DecisionState.ALLOW:
            verified = VerifiedRelease(
                verification_id=f"verification:{candidate.candidate_id}",
                candidate_id=candidate.candidate_id,
                component_id=candidate.manifest.component_id,
                kind=candidate.manifest.kind,
                artifact_digest=actual_digest,
                tenant=candidate.manifest.tenant,
                environment=candidate.manifest.environment,
                capabilities=candidate.manifest.capabilities,
                signer_identity=candidate.attestation.signer_identity,
                builder_id=statement.builder_id,
                source_uri=statement.source_uri,
                source_commit=statement.source_commit,
                inventory_id=candidate.inventory.inventory_id,
                scan_id=candidate.scan.scan_id,
                receipt_id=receipt.receipt_id,
                policy_version=POLICY_VERSION,
            )
            self.verified[verified.verification_id] = verified
        decision = Decision(state, reason, receipt, verified=verified)
        self.candidate_index[candidate.candidate_id] = fingerprint
        self.candidate_results[candidate.candidate_id] = decision
        return decision

    def start_canary(
        self,
        principal: Principal,
        verification_id: str,
        deployment_id: str,
        *,
        now: int,
        step: int,
    ) -> Decision:
        verified = self.verified.get(verification_id)
        fingerprint = _digest((verification_id, deployment_id))
        prior = self.deployment_index.get(deployment_id)
        if prior:
            deployment = self.deployments.get(deployment_id)
            if prior == fingerprint and deployment:
                receipt = next(
                    item for item in self.receipts if item.receipt_id == deployment.receipt_id
                )
                return Decision(
                    DecisionState.ALLOW,
                    "canary-authorized",
                    receipt,
                    deployment=deployment,
                    replayed=True,
                )
            receipt = self._record(
                stage="canary",
                state=DecisionState.DENY,
                reason="deployment-replay-mismatch",
                step=step,
                actor=principal.subject,
            )
            return Decision(DecisionState.DENY, receipt.reason, receipt)

        state, reason = DecisionState.ALLOW, "canary-authorized"
        if not self.rollout_store_available:
            state, reason = DecisionState.ERROR, "rollout-store-unavailable"
        elif not self.policy_store_available:
            state, reason = DecisionState.ERROR, "policy-store-unavailable"
        elif not verified:
            state, reason = DecisionState.DENY, "verification-missing"
        elif not principal.authenticated or principal.tenant != verified.tenant:
            state, reason = DecisionState.DENY, "deployer-identity"
        elif "release.deploy" not in principal.roles:
            state, reason = DecisionState.DENY, "deployer-role"
        elif verified.policy_version != POLICY_VERSION:
            state, reason = DecisionState.DENY, "policy-stale"
        elif verified.artifact_digest in self.revoked_digests:
            state, reason = DecisionState.DENY, "artifact-revoked"

        receipt = self._record(
            stage="canary",
            state=state,
            reason=reason,
            step=step,
            actor=principal.subject,
            component_id=verified.component_id if verified else "",
            digest=verified.artifact_digest if verified else "",
            tenant=verified.tenant if verified else "",
            environment=verified.environment if verified else "",
            parent_receipt_id=verified.receipt_id if verified else "",
        )
        deployment = None
        if state is DecisionState.ALLOW and verified:
            deployment = Deployment(
                deployment_id=deployment_id,
                verification_id=verification_id,
                component_id=verified.component_id,
                artifact_digest=verified.artifact_digest,
                previous_digest=self.current_digests[verified.component_id],
                tenant=verified.tenant,
                environment=verified.environment,
                stage=DeploymentStage.CANARY,
                receipt_id=receipt.receipt_id,
                started_at=now,
            )
            self.deployments[deployment_id] = deployment
            self.deployment_index[deployment_id] = fingerprint
        return Decision(state, reason, receipt, deployment=deployment)

    def promote(
        self,
        principal: Principal,
        proposal: PromotionProposal,
        *,
        now: int,
        step: int,
    ) -> Decision:
        fingerprint = _digest(proposal)
        prior = self.promotion_index.get(proposal.promotion_id)
        if prior:
            if prior == fingerprint:
                return replace(
                    self.promotion_results[proposal.promotion_id], replayed=True
                )
            receipt = self._record(
                stage="promote",
                state=DecisionState.DENY,
                reason="promotion-replay-mismatch",
                step=step,
                actor=principal.subject,
            )
            return Decision(DecisionState.DENY, receipt.reason, receipt)

        deployment = self.deployments.get(proposal.deployment_id)
        verified = self.verified.get(proposal.verification_id)
        observation = proposal.observation
        state, reason = DecisionState.ALLOW, "promotion-authorized"
        if not self.rollout_store_available:
            state, reason = DecisionState.ERROR, "rollout-store-unavailable"
        elif not self.policy_store_available:
            state, reason = DecisionState.ERROR, "policy-store-unavailable"
        elif not deployment or not verified:
            state, reason = DecisionState.DENY, "promotion-state"
        elif not principal.authenticated or "release.promote" not in principal.roles:
            state, reason = DecisionState.DENY, "promoter-role"
        elif principal.tenant != proposal.tenant or principal.tenant != deployment.tenant:
            state, reason = DecisionState.DENY, "promoter-tenant"
        elif proposal.environment != deployment.environment or deployment.stage is not DeploymentStage.CANARY:
            state, reason = DecisionState.DENY, "promotion-scope"
        elif deployment.verification_id != proposal.verification_id or verified.artifact_digest != deployment.artifact_digest:
            state, reason = DecisionState.DENY, "promotion-binding"
        elif verified.artifact_digest in self.revoked_digests:
            state, reason = DecisionState.DENY, "artifact-revoked"
        elif observation.deployment_id != deployment.deployment_id or observation.artifact_digest != deployment.artifact_digest:
            state, reason = DecisionState.DENY, "observation-binding"
        elif observation.started_at < deployment.started_at or observation.ended_at > now or observation.ended_at <= observation.started_at:
            state, reason = DecisionState.DENY, "observation-window"
        elif observation.sample_count < 100:
            state, reason = DecisionState.STOP, "canary-insufficient-samples"
        elif observation.error_rate > 0.01 or observation.forbidden_action_count or observation.provenance_failure_count:
            state, reason = DecisionState.STOP, "canary-threshold"

        receipt = self._record(
            stage="promote",
            state=state,
            reason=reason,
            step=step,
            actor=principal.subject,
            component_id=deployment.component_id if deployment else "",
            digest=deployment.artifact_digest if deployment else "",
            tenant=proposal.tenant,
            environment=proposal.environment,
            parent_receipt_id=deployment.receipt_id if deployment else "",
        )
        promoted = None
        if state is DecisionState.ALLOW and deployment:
            promoted = replace(
                deployment,
                stage=DeploymentStage.PRODUCTION,
                receipt_id=receipt.receipt_id,
            )
            self.deployments[deployment.deployment_id] = promoted
            self.current_digests[deployment.component_id] = deployment.artifact_digest
        decision = Decision(state, reason, receipt, deployment=promoted)
        self.promotion_index[proposal.promotion_id] = fingerprint
        self.promotion_results[proposal.promotion_id] = decision
        return decision

    def issue_rollback_guard(
        self,
        principal: Principal,
        deployment_id: str,
        incident_id: str,
        guard_id: str,
        *,
        now: int,
        ttl: int = 120,
        step: int,
    ) -> Decision:
        deployment = self.deployments.get(deployment_id)
        fingerprint = _digest((deployment_id, incident_id, guard_id))
        prior = self.guard_index.get(guard_id)
        state, reason = DecisionState.ALLOW, "rollback-guard-issued"
        if prior:
            state, reason = DecisionState.DENY, "rollback-guard-replay"
        elif not self.rollout_store_available:
            state, reason = DecisionState.ERROR, "rollout-store-unavailable"
        elif not deployment or deployment.stage is not DeploymentStage.PRODUCTION:
            state, reason = DecisionState.DENY, "rollback-state"
        elif not principal.authenticated or "rollback.issue" not in principal.roles:
            state, reason = DecisionState.DENY, "rollback-issuer-role"
        elif principal.tenant != deployment.tenant:
            state, reason = DecisionState.DENY, "rollback-issuer-tenant"
        elif not incident_id or ttl < 1 or ttl > 300:
            state, reason = DecisionState.DENY, "rollback-guard-contract"

        receipt = self._record(
            stage="rollback-issue",
            state=state,
            reason=reason,
            step=step,
            actor=principal.subject,
            component_id=deployment.component_id if deployment else "",
            digest=deployment.artifact_digest if deployment else "",
            tenant=deployment.tenant if deployment else "",
            environment=deployment.environment if deployment else "",
            parent_receipt_id=deployment.receipt_id if deployment else "",
        )
        guard = None
        if state is DecisionState.ALLOW and deployment:
            guard = RollbackGuard(
                guard_id=guard_id,
                deployment_id=deployment_id,
                component_id=deployment.component_id,
                failed_digest=deployment.artifact_digest,
                target_digest=deployment.previous_digest,
                incident_id=incident_id,
                tenant=deployment.tenant,
                environment=deployment.environment,
                issued_at=now,
                expires_at=now + ttl,
            )
            self.rollback_guards[guard_id] = guard
            self.guard_index[guard_id] = fingerprint
        return Decision(state, reason, receipt, rollback_guard=guard)

    def consume_rollback(
        self,
        principal: Principal,
        guard_id: str,
        *,
        now: int,
        step: int,
    ) -> Decision:
        guard = self.rollback_guards.get(guard_id)
        deployment = self.deployments.get(guard.deployment_id) if guard else None
        state, reason = DecisionState.ALLOW, "rollback-completed"
        if not self.rollout_store_available:
            state, reason = DecisionState.ERROR, "rollout-store-unavailable"
        elif not guard or not deployment:
            state, reason = DecisionState.DENY, "rollback-guard-missing"
        elif guard.consumed:
            state, reason = DecisionState.DENY, "rollback-guard-consumed"
        elif guard.expires_at <= now:
            state, reason = DecisionState.DENY, "rollback-guard-expired"
        elif not principal.authenticated or "rollback.execute" not in principal.roles:
            state, reason = DecisionState.DENY, "rollback-executor-role"
        elif principal.tenant != guard.tenant:
            state, reason = DecisionState.DENY, "rollback-executor-tenant"
        elif deployment.stage is not DeploymentStage.PRODUCTION or self.current_digests.get(guard.component_id) != guard.failed_digest:
            state, reason = DecisionState.DENY, "rollback-current-state"

        receipt = self._record(
            stage="rollback",
            state=state,
            reason=reason,
            step=step,
            actor=principal.subject,
            component_id=guard.component_id if guard else "",
            digest=guard.target_digest if guard else "",
            tenant=guard.tenant if guard else "",
            environment=guard.environment if guard else "",
            parent_receipt_id=deployment.receipt_id if deployment else "",
        )
        result = None
        if state is DecisionState.ALLOW and guard and deployment:
            consumed = replace(guard, consumed=True)
            self.rollback_guards[guard_id] = consumed
            rolled_back = replace(
                deployment,
                stage=DeploymentStage.ROLLED_BACK,
                receipt_id=receipt.receipt_id,
            )
            self.deployments[deployment.deployment_id] = rolled_back
            self.current_digests[guard.component_id] = guard.target_digest
            result = RollbackResult(
                guard_id=guard.guard_id,
                deployment_id=guard.deployment_id,
                restored_digest=guard.target_digest,
                incident_id=guard.incident_id,
                duration_seconds=now - guard.issued_at,
                receipt_id=receipt.receipt_id,
            )
        return Decision(state, reason, receipt, rollback=result)


def _component_config(kind: ComponentKind) -> dict[str, object]:
    slug = kind.value
    capabilities = {
        ComponentKind.PROMPT_BUNDLE: frozenset({"support.summarize"}),
        ComponentKind.POLICY_BUNDLE: frozenset({"policy.evaluate"}),
        ComponentKind.PLUGIN: frozenset({"ticket.read"}),
        ComponentKind.MCP_SERVER: frozenset({"case.lookup"}),
        ComponentKind.MODEL_ADAPTER: frozenset({"model.invoke"}),
    }[kind]
    commit = _digest(f"approved-source:{slug}")[:40]
    return {
        "component_id": f"agent-platform/{slug}",
        "source_uri": f"git+https://github.com/example/agent-{slug}",
        "source_commit": commit,
        "builder_id": "https://github.com/actions/runner/github-hosted",
        "build_type": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
        "workflow_digest": _digest(f".github/workflows/release-{slug}.yml@v3"),
        "signer_identity": f"https://github.com/example/agent-{slug}/.github/workflows/release.yml@refs/heads/main",
        "signer_issuer": "https://token.actions.githubusercontent.com",
        "capabilities": capabilities,
    }


def _public_bytes(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_statement(
    statement: ProvenanceStatement,
    *,
    signer_identity: str,
    signer_issuer: str,
) -> SignedAttestation:
    private = _private_key(f"teaching-key:{signer_identity}:{signer_issuer}")
    signature = base64.b64encode(private.sign(_canonical(statement))).decode()
    return SignedAttestation(
        signer_identity=signer_identity,
        signer_issuer=signer_issuer,
        statement=statement,
        signature=signature,
    )


def candidate_for(
    kind: ComponentKind = ComponentKind.MCP_SERVER,
    *,
    candidate_id: str | None = None,
) -> ReleaseCandidate:
    config = _component_config(kind)
    content = (
        f"component={kind.value}\nversion=2.4.0\n"
        f"capabilities={','.join(sorted(config['capabilities']))}\n"
    ).encode()
    artifact = Artifact(
        name=f"registry.example.test/{kind.value}@2.4.0",
        kind=kind,
        content=content,
    )
    dependencies = (
        ArtifactReference(
            "runtime-base",
            f"sha256:{_digest('runtime-base@3.12.8')}",
            _digest("runtime-base@3.12.8"),
        ),
        ArtifactReference(
            "policy-runtime",
            f"sha256:{_digest('policy-runtime@1.9.2')}",
            _digest("policy-runtime@1.9.2"),
        ),
    )
    manifest = ComponentManifest(
        component_id=config["component_id"],
        kind=kind,
        version="2.4.0",
        artifact_ref=f"sha256:{artifact.digest}",
        artifact_digest=artifact.digest,
        tenant="north",
        environment="production",
        capabilities=config["capabilities"],
        dependencies=dependencies,
    )
    statement = ProvenanceStatement(
        statement_type=IN_TOTO_STATEMENT_TYPE,
        predicate_type=SLSA_PROVENANCE_TYPE,
        subject_name=artifact.name,
        subject_digest=artifact.digest,
        builder_id=config["builder_id"],
        build_type=config["build_type"],
        source_uri=config["source_uri"],
        source_commit=config["source_commit"],
        workflow_digest=config["workflow_digest"],
        resolved_dependencies=dependencies,
        tenant="north",
        environment="production",
        issued_at=NOW - 60,
        expires_at=NOW + 3600,
    )
    attestation = sign_statement(
        statement,
        signer_identity=config["signer_identity"],
        signer_issuer=config["signer_issuer"],
    )
    inventory = Inventory(
        inventory_id=f"inventory:{kind.value}:2.4.0",
        subject_digest=artifact.digest,
        format_name="CycloneDX",
        format_version="1.7",
        complete=True,
        components=dependencies,
        generated_at=NOW - 55,
    )
    scan = ScanEvidence(
        scan_id=f"scan:{kind.value}:2.4.0",
        subject_digest=artifact.digest,
        scanner="synthetic-osv-snapshot",
        scanner_version="2026-10-30",
        critical_findings=0,
        high_findings=1,
        generated_at=NOW - 50,
    )
    return ReleaseCandidate(
        candidate_id=candidate_id or f"candidate:{kind.value}:2.4.0",
        artifact=artifact,
        manifest=manifest,
        attestation=attestation,
        inventory=inventory,
        scan=scan,
    )


def resign(
    candidate: ReleaseCandidate,
    statement: ProvenanceStatement,
    *,
    signer_identity: str | None = None,
    signer_issuer: str | None = None,
) -> ReleaseCandidate:
    identity = signer_identity or candidate.attestation.signer_identity
    issuer = signer_issuer or candidate.attestation.signer_issuer
    return replace(
        candidate,
        attestation=sign_statement(
            statement, signer_identity=identity, signer_issuer=issuer
        ),
    )


def build_scenario() -> tuple[
    SupplyChainReleaseGate,
    dict[str, Principal],
    dict[ComponentKind, ReleaseCandidate],
]:
    policies: dict[ComponentKind, ReleasePolicy] = {}
    signers: dict[tuple[str, str], bytes] = {}
    previous: dict[str, str] = {}
    candidates: dict[ComponentKind, ReleaseCandidate] = {}
    for kind in ComponentKind:
        config = _component_config(kind)
        candidate = candidate_for(kind)
        candidates[kind] = candidate
        policies[kind] = ReleasePolicy(
            component_id=config["component_id"],
            kind=kind,
            tenant="north",
            environment="production",
            allowed_capabilities=config["capabilities"],
            source_uri=config["source_uri"],
            approved_source_commits=frozenset({config["source_commit"]}),
            builder_id=config["builder_id"],
            build_type=config["build_type"],
            workflow_digest=config["workflow_digest"],
            signer_identity=config["signer_identity"],
            signer_issuer=config["signer_issuer"],
        )
        private = _private_key(
            f"teaching-key:{config['signer_identity']}:{config['signer_issuer']}"
        )
        signers[(config["signer_identity"], config["signer_issuer"])] = (
            _public_bytes(private)
        )
        previous[config["component_id"]] = _digest(
            f"last-known-good:{kind.value}:2.3.1"
        )
    principals = {
        "verifier": Principal(
            "release-verifier", "north", frozenset({"release.verify"})
        ),
        "deployer": Principal(
            "release-deployer",
            "north",
            frozenset({"release.deploy", "release.promote", "rollback.execute"}),
        ),
        "monitor": Principal(
            "health-monitor", "north", frozenset({"rollback.issue"})
        ),
        "other": Principal(
            "other-tenant-verifier", "south", frozenset({"release.verify"})
        ),
    }
    return SupplyChainReleaseGate(policies, signers, previous), principals, candidates


def healthy_observation(deployment: Deployment, *, suffix: str = "1") -> CanaryObservation:
    return CanaryObservation(
        observation_id=f"observation:{suffix}",
        deployment_id=deployment.deployment_id,
        artifact_digest=deployment.artifact_digest,
        sample_count=500,
        error_rate=0.002,
        forbidden_action_count=0,
        provenance_failure_count=0,
        started_at=deployment.started_at,
        ended_at=deployment.started_at + 10,
    )


def run_valid_release(
    kind: ComponentKind = ComponentKind.MCP_SERVER,
    *,
    suffix: str = "default",
) -> ReleaseFlow:
    gate, principals, candidates = build_scenario()
    candidate = replace(
        candidates[kind], candidate_id=f"candidate:{kind.value}:{suffix}"
    )
    verification = gate.verify_candidate(
        principals["verifier"], candidate, now=NOW, step=0
    )
    assert verification.allowed and verification.verified
    canary = gate.start_canary(
        principals["deployer"],
        verification.verified.verification_id,
        f"deployment:{kind.value}:{suffix}",
        now=NOW + 1,
        step=1,
    )
    assert canary.allowed and canary.deployment
    observation = healthy_observation(canary.deployment, suffix=suffix)
    promotion = gate.promote(
        principals["deployer"],
        PromotionProposal(
            f"promotion:{kind.value}:{suffix}",
            canary.deployment.deployment_id,
            verification.verified.verification_id,
            "north",
            "production",
            observation,
        ),
        now=NOW + 12,
        step=2,
    )
    assert promotion.allowed and promotion.deployment
    return ReleaseFlow(gate, principals, verification, canary, promotion)


def unsafe_supply_chain_baseline() -> UnsafeBaseline:
    return UnsafeBaseline(
        release_candidates=5,
        cryptographically_verified=1,
        referenced_components=15,
        pinned_components=5,
        provenance_attack_cases=8,
        detected_provenance_failures=0,
        attack_cases=4,
        forbidden_releases=4,
        rollback_seconds=(900, 1200),
    )


def _attack_decisions() -> list[tuple[str, Decision, bool]]:
    attacks: list[tuple[str, Decision, bool]] = []

    def evaluate(
        name: str,
        mutation,
        *,
        provenance: bool = False,
    ) -> None:
        gate, principals, candidates = build_scenario()
        candidate = mutation(candidates[ComponentKind.MCP_SERVER])
        decision = gate.verify_candidate(
            principals["verifier"], candidate, now=NOW, step=0
        )
        attacks.append((name, decision, provenance))

    evaluate(
        "mutable-root-reference",
        lambda item: replace(
            item, manifest=replace(item.manifest, artifact_ref="registry.example.test/mcp-server:latest")
        ),
    )
    evaluate(
        "artifact-substitution",
        lambda item: replace(
            item,
            artifact=replace(item.artifact, content=b"malicious substituted payload"),
        ),
        provenance=True,
    )
    evaluate(
        "signature-forgery",
        lambda item: replace(
            item,
            attestation=replace(item.attestation, signature=base64.b64encode(b"0" * 64).decode()),
        ),
        provenance=True,
    )
    evaluate(
        "signer-substitution",
        lambda item: resign(
            item,
            item.attestation.statement,
            signer_identity="https://github.com/attacker/release.yml",
        ),
        provenance=True,
    )
    evaluate(
        "issuer-substitution",
        lambda item: resign(
            item,
            item.attestation.statement,
            signer_issuer="https://attacker.example/oidc",
        ),
        provenance=True,
    )
    evaluate(
        "builder-substitution",
        lambda item: resign(
            item,
            replace(item.attestation.statement, builder_id="https://runner.attacker.example"),
        ),
        provenance=True,
    )
    evaluate(
        "source-substitution",
        lambda item: resign(
            item,
            replace(item.attestation.statement, source_uri="git+https://github.com/attacker/mcp"),
        ),
        provenance=True,
    )
    evaluate(
        "source-ref-not-immutable",
        lambda item: resign(
            item,
            replace(item.attestation.statement, source_commit="refs/heads/main"),
        ),
        provenance=True,
    )
    evaluate(
        "stale-provenance",
        lambda item: resign(
            item,
            replace(item.attestation.statement, issued_at=NOW - 7200, expires_at=NOW + 10),
        ),
        provenance=True,
    )
    evaluate(
        "workflow-substitution",
        lambda item: resign(
            item,
            replace(item.attestation.statement, workflow_digest=_digest("attacker workflow")),
        ),
        provenance=True,
    )
    evaluate(
        "capability-widening",
        lambda item: replace(
            item,
            manifest=replace(
                item.manifest,
                capabilities=item.manifest.capabilities | {"records.export"},
            ),
        ),
    )
    evaluate(
        "unpinned-dependency",
        lambda item: replace(
            item,
            manifest=replace(
                item.manifest,
                dependencies=(
                    replace(item.manifest.dependencies[0], uri="python:3.12-latest"),
                    item.manifest.dependencies[1],
                ),
            ),
        ),
    )
    evaluate(
        "incomplete-inventory",
        lambda item: replace(
            item, inventory=replace(item.inventory, complete=False, components=item.inventory.components[:1])
        ),
    )
    evaluate(
        "critical-vulnerability",
        lambda item: replace(item, scan=replace(item.scan, critical_findings=1)),
    )
    return attacks


def _failure_decisions() -> list[tuple[str, Decision]]:
    failures: list[tuple[str, Decision]] = []
    for attribute, name in (
        ("trust_store_available", "trust-store-failure"),
        ("policy_store_available", "policy-store-failure"),
        ("inventory_service_available", "inventory-service-failure"),
    ):
        gate, principals, candidates = build_scenario()
        setattr(gate, attribute, False)
        decision = gate.verify_candidate(
            principals["verifier"],
            replace(candidates[ComponentKind.MCP_SERVER], candidate_id=f"failure:{name}"),
            now=NOW,
            step=0,
        )
        failures.append((name, decision))
    return failures


def _recovery_case(kind: ComponentKind, duration: int) -> tuple[Decision, Decision]:
    flow = run_valid_release(kind, suffix=f"recovery-{duration}")
    deployment = flow.promotion.deployment
    assert deployment
    issued = flow.gate.issue_rollback_guard(
        flow.principals["monitor"],
        deployment.deployment_id,
        f"incident:{kind.value}",
        f"guard:{kind.value}:{duration}",
        now=NOW + 20,
        step=3,
    )
    assert issued.allowed
    rollback = flow.gate.consume_rollback(
        flow.principals["deployer"],
        issued.rollback_guard.guard_id,
        now=NOW + 20 + duration,
        step=4,
    )
    return issued, rollback


def evaluate_controls() -> tuple[EvaluationReport, tuple[ControlCase, ...]]:
    valid_flows = tuple(
        run_valid_release(kind, suffix=f"valid-{index}")
        for index, kind in enumerate(ComponentKind, start=1)
    )
    attacks = _attack_decisions()
    failures = _failure_decisions()
    recoveries = (
        _recovery_case(ComponentKind.MCP_SERVER, 12),
        _recovery_case(ComponentKind.POLICY_BUNDLE, 14),
    )

    cases: list[ControlCase] = []
    for index, flow in enumerate(valid_flows, start=1):
        cases.append(
            ControlCase(
                f"valid-{index}",
                "valid",
                flow.promotion.state,
                flow.promotion.reason,
                False,
                bool(flow.promotion.receipt.receipt_id),
            )
        )
    for name, decision, provenance in attacks:
        cases.append(
            ControlCase(
                name,
                "attack",
                decision.state,
                decision.reason,
                decision.allowed,
                bool(decision.receipt.receipt_id),
                provenance_attack=provenance,
            )
        )
    for name, decision in failures:
        cases.append(
            ControlCase(
                name,
                "failure",
                decision.state,
                decision.reason,
                False,
                bool(decision.receipt.receipt_id),
            )
        )
    for index, (_, rollback) in enumerate(recoveries, start=1):
        cases.append(
            ControlCase(
                f"recovery-{index}",
                "recovery",
                rollback.state,
                rollback.reason,
                False,
                bool(rollback.receipt.receipt_id),
                rollback_seconds=(
                    rollback.rollback.duration_seconds if rollback.rollback else None
                ),
            )
        )

    valid_components = [
        reference
        for flow in valid_flows
        for reference in (
            candidate_for(flow.verification.verified.kind).manifest.artifact_ref,
            *[
                item.uri
                for item in candidate_for(
                    flow.verification.verified.kind
                ).manifest.dependencies
            ],
        )
    ]
    unpinned = sum(
        not (
            (value.startswith("sha256:") and len(value) == 71)
            or (len(value) == 64 and all(c in "0123456789abcdef" for c in value))
        )
        for value in valid_components
    )
    provenance_cases = [case for case in cases if case.provenance_attack]
    rollback_times = [
        case.rollback_seconds
        for case in cases
        if case.category == "recovery" and case.rollback_seconds is not None
    ]
    baseline = unsafe_supply_chain_baseline()
    report = EvaluationReport(
        total_cases=len(cases),
        valid_cases=len(valid_flows),
        attack_cases=len(attacks),
        failure_cases=len(failures),
        recovery_cases=len(recoveries),
        valid_deployment_completion_rate=sum(
            flow.promotion.allowed for flow in valid_flows
        )
        / len(valid_flows),
        verified_artifact_coverage=sum(
            bool(flow.verification.verified) for flow in valid_flows
        )
        / len(valid_flows),
        unpinned_component_rate=unpinned / len(valid_components),
        provenance_failures=len(provenance_cases),
        provenance_failure_detection_rate=sum(
            not case.unauthorized_release for case in provenance_cases
        )
        / len(provenance_cases),
        forbidden_release_rate=sum(
            case.unauthorized_release for case in cases if case.category == "attack"
        )
        / len(attacks),
        failure_error_rate=sum(
            case.state is DecisionState.ERROR
            for case in cases
            if case.category == "failure"
        )
        / len(failures),
        rollback_success_rate=sum(
            case.state is DecisionState.ALLOW
            for case in cases
            if case.category == "recovery"
        )
        / len(recoveries),
        median_rollback_seconds=float(median(rollback_times)),
        maximum_rollback_seconds=max(rollback_times),
        audit_coverage_rate=sum(case.receipt_present for case in cases) / len(cases),
        unsafe_baseline_forbidden_release_rate=baseline.forbidden_release_rate,
    )
    return report, tuple(cases)


def demo() -> None:
    report, _ = evaluate_controls()
    print(asdict(report))


if __name__ == "__main__":
    demo()
