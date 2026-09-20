"""Evidence-bound production release gate for an enterprise AI agent.

The lab uses HMAC attestations and in-memory state so it remains credential-free.
Production systems should replace both with workload identity, verifiable
attestations, protected policy distribution, and durable transactional state.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import hmac
import json
from threading import Lock
from typing import Any, Mapping, TypeAlias


class EvidenceResult(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"


class DecisionState(str, Enum):
    READY = "ready"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class ReleaseCandidate:
    release_id: str
    tenant: str
    environment: str
    artifact_digest: str
    source_revision: str
    model_version: str
    prompt_version: str
    toolset_version: str
    requested_by: str


@dataclass(frozen=True)
class EvidenceArtifact:
    evidence_id: str
    kind: str
    subject_digest: str
    tenant: str
    environment: str
    policy_version: str
    producer: str
    owner: str
    uri: str
    payload_digest: str
    observed_at: datetime
    result: EvidenceResult


@dataclass(frozen=True)
class ControlEvidence:
    artifact: EvidenceArtifact


@dataclass(frozen=True)
class AttackEvaluation:
    artifact: EvidenceArtifact
    expected_attempts: int
    executed_attempts: int
    severe_attack_successes: int
    harness_errors: int


@dataclass(frozen=True)
class TraceCoverage:
    artifact: EvidenceArtifact
    expected_critical_operations: int
    traced_critical_operations: int
    collection_errors: int


@dataclass(frozen=True)
class RollbackDrill:
    artifact: EvidenceArtifact
    required_steps: int
    verified_steps: int
    duration_seconds: int
    recovery_point_verified: bool


Evidence: TypeAlias = ControlEvidence | AttackEvaluation | TraceCoverage | RollbackDrill


@dataclass(frozen=True)
class EvidenceEnvelope:
    payload: Evidence
    integrity_tag: str


@dataclass(frozen=True)
class RiskAcceptance:
    acceptance_id: str
    risk_id: str
    subject_digest: str
    tenant: str
    environment: str
    policy_version: str
    owner: str
    approver: str
    rationale: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class RiskEnvelope:
    payload: RiskAcceptance
    integrity_tag: str


@dataclass(frozen=True)
class PrincipalRecord:
    tenant: str
    roles: frozenset[str]
    verification_key: bytes
    active: bool = True


@dataclass(frozen=True)
class ActorContext:
    subject: str
    tenant: str
    authenticated: bool = True


@dataclass(frozen=True)
class EvidenceRequirement:
    kind: str
    trusted_producers: frozenset[str]
    maximum_age: timedelta


@dataclass(frozen=True)
class ReleasePolicy:
    version: str
    requirements: tuple[EvidenceRequirement, ...]
    maximum_rollback_seconds: int
    risk_approver_role: str
    release_approver_role: str
    authorization_ttl: timedelta


@dataclass(frozen=True)
class ReleaseDecision:
    state: DecisionState
    blockers: tuple[str, ...]
    release_id: str
    subject_digest: str
    tenant: str
    environment: str
    policy_version: str
    evidence_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    risk_acceptance_ids: tuple[str, ...]
    accountable_principals: tuple[str, ...]
    decided_at: datetime
    decision_id: str
    integrity_tag: str

    @property
    def ready(self) -> bool:
        return self.state is DecisionState.READY


@dataclass(frozen=True)
class DeploymentAuthorization:
    authorization_id: str
    decision_id: str
    release_id: str
    subject_digest: str
    tenant: str
    environment: str
    policy_version: str
    approver: str
    issued_at: datetime
    expires_at: datetime
    integrity_tag: str


@dataclass(frozen=True)
class AuthorizationResult:
    allowed: bool
    reason: str
    authorization: DeploymentAuthorization | None


@dataclass(frozen=True)
class DeploymentReceipt:
    allowed: bool
    reason: str
    authorization_id: str
    release_id: str
    consumed_at: datetime | None


def _canonical(value: Any) -> Any:
    if is_dataclass(value):
        return {field.name: _canonical(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (set, frozenset)):
        return sorted(_canonical(item) for item in value)
    if isinstance(value, (tuple, list)):
        return [_canonical(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in sorted(value.items())}
    return value


def _bytes(value: Any) -> bytes:
    return json.dumps(_canonical(value), sort_keys=True, separators=(",", ":")).encode()


def _tag(value: Any, key: bytes) -> str:
    return hmac.new(key, _bytes(value), sha256).hexdigest()


def _digest(value: str) -> str:
    return "sha256:" + sha256(value.encode()).hexdigest()


def _valid_digest(value: str) -> bool:
    prefix, separator, digest = value.partition(":")
    return separator == ":" and prefix == "sha256" and len(digest) == 64 and all(
        character in "0123456789abcdef" for character in digest
    )


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def candidate_binding(candidate: ReleaseCandidate) -> str:
    """Digest every security-relevant candidate field into one review subject."""

    return _digest(_bytes(candidate).decode())


def artifact_for(payload: Evidence) -> EvidenceArtifact:
    return payload.artifact


def attest_evidence(payload: Evidence, signing_key: bytes) -> EvidenceEnvelope:
    """Create a local teaching attestation over the entire typed payload."""

    return EvidenceEnvelope(payload, _tag(payload, signing_key))


def attest_risk(payload: RiskAcceptance, signing_key: bytes) -> RiskEnvelope:
    return RiskEnvelope(payload, _tag(payload, signing_key))


class EvidenceRegistry:
    """Verify evidence producer identity; artifact URIs are never trusted directly."""

    def __init__(self, producer_keys: Mapping[str, bytes]) -> None:
        self._producer_keys = dict(producer_keys)

    def verify(self, envelope: EvidenceEnvelope) -> bool:
        producer = artifact_for(envelope.payload).producer
        key = self._producer_keys.get(producer)
        return bool(key) and hmac.compare_digest(envelope.integrity_tag, _tag(envelope.payload, key))


class HumanDirectory:
    """Resolve current tenant, role, activity, and verification key server-side."""

    def __init__(self, records: Mapping[str, PrincipalRecord]) -> None:
        self._records = dict(records)

    def authorized(self, actor: ActorContext, role: str) -> bool:
        record = self._records.get(actor.subject)
        return bool(
            actor.authenticated
            and record
            and record.active
            and record.tenant == actor.tenant
            and role in record.roles
        )

    def verify_risk(self, envelope: RiskEnvelope) -> bool:
        record = self._records.get(envelope.payload.approver)
        return bool(
            record
            and record.active
            and hmac.compare_digest(
                envelope.integrity_tag,
                _tag(envelope.payload, record.verification_key),
            )
        )


def default_policy() -> ReleasePolicy:
    age = timedelta(days=30)
    producers = {
        "threat-model": "risk-platform",
        "policy-tests": "policy-ci",
        "attack-evaluation": "attack-harness",
        "trace-coverage": "telemetry-ci",
        "rollback-drill": "sre-drill",
        "control-owner": "governance-registry",
        "artifact-provenance": "build-verifier",
    }
    return ReleasePolicy(
        version="release-policy/v3",
        requirements=tuple(
            EvidenceRequirement(kind, frozenset({producer}), age)
            for kind, producer in producers.items()
        ),
        maximum_rollback_seconds=900,
        risk_approver_role="risk-approver",
        release_approver_role="release-approver",
        authorization_ttl=timedelta(minutes=10),
    )


class ReleaseGate:
    """Admit authentic evidence, decide readiness, and authorize exact deployment."""

    def __init__(
        self,
        policy: ReleasePolicy,
        evidence_registry: EvidenceRegistry,
        human_directory: HumanDirectory,
        receipt_key: bytes,
    ) -> None:
        self.policy = policy
        self.evidence_registry = evidence_registry
        self.human_directory = human_directory
        self._receipt_key = receipt_key

    def evaluate(
        self,
        candidate: ReleaseCandidate,
        evidence: list[EvidenceEnvelope],
        residual_risks: list[RiskEnvelope],
        *,
        now: datetime,
    ) -> ReleaseDecision:
        if not _aware(now):
            raise ValueError("now must be timezone-aware")

        incomplete: list[str] = []
        failed: list[str] = []
        candidate_fields = (
            candidate.release_id,
            candidate.tenant,
            candidate.environment,
            candidate.source_revision,
            candidate.model_version,
            candidate.prompt_version,
            candidate.toolset_version,
            candidate.requested_by,
        )
        if not all(item.strip() for item in candidate_fields) or not _valid_digest(candidate.artifact_digest):
            incomplete.append("incomplete:invalid-release-candidate")
        requirements = {item.kind: item for item in self.policy.requirements}
        by_kind: dict[str, list[EvidenceEnvelope]] = {}
        ids: dict[str, int] = {}
        for envelope in evidence:
            artifact = artifact_for(envelope.payload)
            by_kind.setdefault(artifact.kind, []).append(envelope)
            ids[artifact.evidence_id] = ids.get(artifact.evidence_id, 0) + 1

        for evidence_id, count in sorted(ids.items()):
            if count > 1:
                incomplete.append(f"incomplete:duplicate-evidence-id:{evidence_id or 'empty'}")
        for kind in sorted(set(by_kind) - set(requirements)):
            incomplete.append(f"incomplete:unexpected-evidence:{kind or 'empty'}")
        for kind in sorted(set(requirements) - set(by_kind)):
            incomplete.append(f"incomplete:missing:{kind}")

        admitted: list[EvidenceEnvelope] = []
        accountable: set[str] = set()
        for kind, requirement in sorted(requirements.items()):
            candidates = by_kind.get(kind, [])
            if len(candidates) != 1:
                if len(candidates) > 1:
                    incomplete.append(f"incomplete:duplicate-kind:{kind}")
                continue
            envelope = candidates[0]
            payload = envelope.payload
            artifact = artifact_for(payload)
            problems = self._admission_problems(candidate, envelope, requirement, now)
            if problems:
                incomplete.extend(problems)
                continue
            admitted.append(envelope)
            accountable.update((artifact.producer, artifact.owner))
            if artifact.result is EvidenceResult.ERROR:
                incomplete.append(f"incomplete:producer-error:{kind}")
                continue
            if artifact.result is EvidenceResult.FAILED:
                failed.append(f"blocked:control-failed:{kind}")
                continue
            shape_problem = self._shape_problem(payload, kind)
            if shape_problem:
                incomplete.append(shape_problem)
                continue
            self._evaluate_claims(payload, failed, incomplete)

        risk_id_counts: dict[str, int] = {}
        for envelope in residual_risks:
            identifier = envelope.payload.acceptance_id
            risk_id_counts[identifier] = risk_id_counts.get(identifier, 0) + 1
        duplicate_risk_ids = {identifier for identifier, count in risk_id_counts.items() if count > 1}
        for identifier in sorted(duplicate_risk_ids):
            incomplete.append(f"incomplete:duplicate-risk-acceptance-id:{identifier or 'empty'}")

        accepted_risks: list[RiskEnvelope] = []
        for envelope in residual_risks:
            risk = envelope.payload
            if risk.acceptance_id in duplicate_risk_ids:
                continue
            problems = self._risk_problems(candidate, envelope, now)
            if problems:
                incomplete.extend(problems)
                continue
            accepted_risks.append(envelope)
            accountable.update((risk.owner, risk.approver))

        state = (
            DecisionState.INCOMPLETE
            if incomplete
            else DecisionState.BLOCKED
            if failed
            else DecisionState.READY
        )
        blockers = tuple(sorted(set([*incomplete, *failed])))
        admitted_artifacts = [artifact_for(item.payload) for item in admitted]
        evidence_ids = tuple(sorted(item.evidence_id for item in admitted_artifacts))
        evidence_digests = tuple(sorted(item.payload_digest for item in admitted_artifacts))
        risk_ids = tuple(sorted(item.payload.acceptance_id for item in accepted_risks))
        decision_material = {
            "state": state.value,
            "blockers": blockers,
            "release_id": candidate.release_id,
            "subject_digest": candidate_binding(candidate),
            "tenant": candidate.tenant,
            "environment": candidate.environment,
            "policy_version": self.policy.version,
            "evidence_ids": evidence_ids,
            "evidence_digests": evidence_digests,
            "risk_acceptance_ids": risk_ids,
            "accountable_principals": tuple(sorted(accountable)),
            "decided_at": now,
        }
        decision_id = _digest(_bytes(decision_material).decode())
        unsigned = ReleaseDecision(
            state,
            blockers,
            candidate.release_id,
            candidate_binding(candidate),
            candidate.tenant,
            candidate.environment,
            self.policy.version,
            evidence_ids,
            evidence_digests,
            risk_ids,
            tuple(sorted(accountable)),
            now,
            decision_id,
            "",
        )
        return replace(unsigned, integrity_tag=_tag(unsigned, self._receipt_key))

    def _admission_problems(
        self,
        candidate: ReleaseCandidate,
        envelope: EvidenceEnvelope,
        requirement: EvidenceRequirement,
        now: datetime,
    ) -> list[str]:
        artifact = artifact_for(envelope.payload)
        kind = requirement.kind
        problems: list[str] = []
        text_fields = (
            artifact.evidence_id,
            artifact.kind,
            artifact.producer,
            artifact.owner,
            artifact.uri,
        )
        if not all(item.strip() for item in text_fields):
            problems.append(f"incomplete:invalid-metadata:{kind}")
        if not _valid_digest(artifact.payload_digest):
            problems.append(f"incomplete:invalid-payload-digest:{kind}")
        if not self.evidence_registry.verify(envelope):
            problems.append(f"incomplete:invalid-attestation:{kind}")
        if artifact.producer not in requirement.trusted_producers:
            problems.append(f"incomplete:untrusted-producer:{kind}")
        if (
            artifact.subject_digest != candidate_binding(candidate)
            or artifact.tenant != candidate.tenant
            or artifact.environment != candidate.environment
        ):
            problems.append(f"incomplete:subject-binding:{kind}")
        if artifact.policy_version != self.policy.version:
            problems.append(f"incomplete:policy-version:{kind}")
        if not _aware(artifact.observed_at):
            problems.append(f"incomplete:naive-time:{kind}")
        elif artifact.observed_at > now or now - artifact.observed_at > requirement.maximum_age:
            problems.append(f"incomplete:stale:{kind}")
        return problems

    @staticmethod
    def _shape_problem(payload: Evidence, kind: str) -> str | None:
        if kind == "attack-evaluation":
            expected_type = AttackEvaluation
        elif kind == "trace-coverage":
            expected_type = TraceCoverage
        elif kind == "rollback-drill":
            expected_type = RollbackDrill
        else:
            expected_type = ControlEvidence
        if not isinstance(payload, expected_type):
            return f"incomplete:evidence-schema:{kind}"
        return None

    def _evaluate_claims(
        self,
        payload: Evidence,
        failed: list[str],
        incomplete: list[str],
    ) -> None:
        if isinstance(payload, AttackEvaluation):
            if min(
                payload.expected_attempts,
                payload.executed_attempts,
                payload.severe_attack_successes,
                payload.harness_errors,
            ) < 0 or payload.expected_attempts == 0:
                incomplete.append("incomplete:invalid-attack-counts")
            elif payload.harness_errors:
                incomplete.append(f"incomplete:attack-harness-errors:{payload.harness_errors}")
            elif payload.executed_attempts != payload.expected_attempts:
                incomplete.append(
                    f"incomplete:attack-coverage:{payload.executed_attempts}/{payload.expected_attempts}"
                )
            if payload.severe_attack_successes:
                failed.append(f"blocked:severe-attack-successes:{payload.severe_attack_successes}")
        elif isinstance(payload, TraceCoverage):
            if min(
                payload.expected_critical_operations,
                payload.traced_critical_operations,
                payload.collection_errors,
            ) < 0 or payload.expected_critical_operations == 0:
                incomplete.append("incomplete:invalid-trace-counts")
            elif payload.collection_errors:
                incomplete.append(f"incomplete:trace-collection-errors:{payload.collection_errors}")
            elif payload.traced_critical_operations != payload.expected_critical_operations:
                failed.append(
                    "blocked:critical-trace-coverage:"
                    f"{payload.traced_critical_operations}/{payload.expected_critical_operations}"
                )
        elif isinstance(payload, RollbackDrill):
            if min(payload.required_steps, payload.verified_steps, payload.duration_seconds) < 0 or payload.required_steps == 0:
                incomplete.append("incomplete:invalid-rollback-measurement")
            else:
                if payload.verified_steps != payload.required_steps:
                    failed.append(
                        f"blocked:rollback-steps:{payload.verified_steps}/{payload.required_steps}"
                    )
                if not payload.recovery_point_verified:
                    failed.append("blocked:rollback-recovery-point")
                if payload.duration_seconds > self.policy.maximum_rollback_seconds:
                    failed.append(
                        "blocked:rollback-duration:"
                        f"{payload.duration_seconds}/{self.policy.maximum_rollback_seconds}"
                    )

    def _risk_problems(
        self,
        candidate: ReleaseCandidate,
        envelope: RiskEnvelope,
        now: datetime,
    ) -> list[str]:
        risk = envelope.payload
        identifier = risk.acceptance_id or "unnamed"
        problems: list[str] = []
        if not all(
            item.strip()
            for item in (
                risk.acceptance_id,
                risk.risk_id,
                risk.owner,
                risk.approver,
                risk.rationale,
            )
        ):
            problems.append(f"incomplete:invalid-risk:{identifier}")
        if not self.human_directory.verify_risk(envelope):
            problems.append(f"incomplete:invalid-risk-attestation:{identifier}")
        actor = ActorContext(risk.approver, risk.tenant)
        if not self.human_directory.authorized(actor, self.policy.risk_approver_role):
            problems.append(f"incomplete:risk-approver-role:{identifier}")
        if risk.owner == risk.approver:
            problems.append(f"incomplete:risk-self-approval:{identifier}")
        if (
            risk.subject_digest != candidate_binding(candidate)
            or risk.tenant != candidate.tenant
            or risk.environment != candidate.environment
        ):
            problems.append(f"incomplete:risk-subject-binding:{identifier}")
        if risk.policy_version != self.policy.version:
            problems.append(f"incomplete:risk-policy-version:{identifier}")
        if not _aware(risk.issued_at) or not _aware(risk.expires_at):
            problems.append(f"incomplete:risk-naive-time:{identifier}")
        elif risk.issued_at > now or risk.expires_at <= now or risk.expires_at <= risk.issued_at:
            problems.append(f"incomplete:risk-time-window:{identifier}")
        return problems

    def verify_decision(self, decision: ReleaseDecision) -> bool:
        unsigned = replace(decision, integrity_tag="")
        return hmac.compare_digest(decision.integrity_tag, _tag(unsigned, self._receipt_key))

    def authorize_deployment(
        self,
        decision: ReleaseDecision,
        candidate: ReleaseCandidate,
        approver: ActorContext,
        *,
        authorization_id: str,
        now: datetime,
    ) -> AuthorizationResult:
        if not authorization_id.strip():
            return AuthorizationResult(False, "authorization-id", None)
        if not _aware(now):
            return AuthorizationResult(False, "naive-time", None)
        if not decision.ready or not self.verify_decision(decision):
            return AuthorizationResult(False, "decision", None)
        if (
            decision.release_id != candidate.release_id
            or decision.subject_digest != candidate_binding(candidate)
            or decision.tenant != candidate.tenant
            or decision.environment != candidate.environment
            or decision.policy_version != self.policy.version
        ):
            return AuthorizationResult(False, "decision-binding", None)
        if not self.human_directory.authorized(approver, self.policy.release_approver_role):
            return AuthorizationResult(False, "approver-role", None)
        if approver.subject == candidate.requested_by or approver.subject in decision.accountable_principals:
            return AuthorizationResult(False, "approver-independence", None)
        unsigned = DeploymentAuthorization(
            authorization_id,
            decision.decision_id,
            candidate.release_id,
            candidate_binding(candidate),
            candidate.tenant,
            candidate.environment,
            self.policy.version,
            approver.subject,
            now,
            now + self.policy.authorization_ttl,
            "",
        )
        token = replace(unsigned, integrity_tag=_tag(unsigned, self._receipt_key))
        return AuthorizationResult(True, "authorized", token)

    def verify_authorization(self, authorization: DeploymentAuthorization) -> bool:
        unsigned = replace(authorization, integrity_tag="")
        return hmac.compare_digest(authorization.integrity_tag, _tag(unsigned, self._receipt_key))


class DeploymentLedger:
    """Atomically consume one exact authorization before a deployer acts."""

    def __init__(self, gate: ReleaseGate) -> None:
        self._gate = gate
        self._lock = Lock()
        self._consumed: set[str] = set()

    def consume(
        self,
        authorization: DeploymentAuthorization,
        candidate: ReleaseCandidate,
        *,
        current_policy_version: str,
        now: datetime,
    ) -> DeploymentReceipt:
        if not _aware(now):
            return DeploymentReceipt(False, "naive-time", authorization.authorization_id, candidate.release_id, None)
        if not self._gate.verify_authorization(authorization):
            return DeploymentReceipt(False, "invalid-authorization", authorization.authorization_id, candidate.release_id, None)
        if (
            authorization.release_id != candidate.release_id
            or authorization.subject_digest != candidate_binding(candidate)
            or authorization.tenant != candidate.tenant
            or authorization.environment != candidate.environment
        ):
            return DeploymentReceipt(False, "authorization-binding", authorization.authorization_id, candidate.release_id, None)
        if authorization.policy_version != current_policy_version:
            return DeploymentReceipt(False, "policy-version", authorization.authorization_id, candidate.release_id, None)
        if now < authorization.issued_at or now >= authorization.expires_at:
            return DeploymentReceipt(False, "authorization-expired", authorization.authorization_id, candidate.release_id, None)
        with self._lock:
            if authorization.authorization_id in self._consumed:
                return DeploymentReceipt(False, "authorization-replayed", authorization.authorization_id, candidate.release_id, None)
            self._consumed.add(authorization.authorization_id)
        return DeploymentReceipt(True, "consumed", authorization.authorization_id, candidate.release_id, now)


DEMO_PRODUCER_KEYS = {
    "risk-platform": b"demo-risk-platform-key",
    "policy-ci": b"demo-policy-ci-key",
    "attack-harness": b"demo-attack-harness-key",
    "telemetry-ci": b"demo-telemetry-ci-key",
    "sre-drill": b"demo-sre-drill-key",
    "governance-registry": b"demo-governance-registry-key",
    "build-verifier": b"demo-build-verifier-key",
}
DEMO_HUMAN_KEYS = {
    "director:risk": b"demo-risk-approver-key",
    "release:operator": b"demo-release-approver-key",
    "developer:agent": b"demo-developer-key",
    "team:agent-security": b"demo-owner-key",
}


def build_scenario(
    *, now: datetime
) -> tuple[
    ReleaseGate,
    ReleaseCandidate,
    list[EvidenceEnvelope],
    list[RiskEnvelope],
    ActorContext,
]:
    policy = default_policy()
    directory = HumanDirectory(
        {
            "director:risk": PrincipalRecord("north", frozenset({"risk-approver"}), DEMO_HUMAN_KEYS["director:risk"]),
            "release:operator": PrincipalRecord("north", frozenset({"release-approver"}), DEMO_HUMAN_KEYS["release:operator"]),
            "developer:agent": PrincipalRecord(
                "north",
                frozenset({"developer", "release-approver"}),
                DEMO_HUMAN_KEYS["developer:agent"],
            ),
            "team:agent-security": PrincipalRecord("north", frozenset({"control-owner"}), DEMO_HUMAN_KEYS["team:agent-security"]),
        }
    )
    gate = ReleaseGate(policy, EvidenceRegistry(DEMO_PRODUCER_KEYS), directory, b"demo-release-gate-key")
    candidate = ReleaseCandidate(
        "release-7",
        "north",
        "production",
        _digest("agent-image@release-7"),
        "git:8a34c1d",
        "support-model/v4",
        "support-prompt/v9",
        "support-tools/v6",
        "developer:agent",
    )
    producer_by_kind = {
        requirement.kind: next(iter(requirement.trusted_producers))
        for requirement in policy.requirements
    }

    def base(kind: str) -> EvidenceArtifact:
        producer = producer_by_kind[kind]
        return EvidenceArtifact(
            f"EV-{kind}",
            kind,
            candidate_binding(candidate),
            candidate.tenant,
            candidate.environment,
            policy.version,
            producer,
            "team:agent-security",
            f"https://evidence.example/releases/{candidate.release_id}/{kind}",
            _digest(f"{candidate.release_id}:{kind}:payload"),
            now - timedelta(hours=6),
            EvidenceResult.PASSED,
        )

    payloads: list[Evidence] = [
        ControlEvidence(base("threat-model")),
        ControlEvidence(base("policy-tests")),
        AttackEvaluation(base("attack-evaluation"), 24, 24, 0, 0),
        TraceCoverage(base("trace-coverage"), 12, 12, 0),
        RollbackDrill(base("rollback-drill"), 8, 8, 420, True),
        ControlEvidence(base("control-owner")),
        ControlEvidence(base("artifact-provenance")),
    ]
    evidence = [
        attest_evidence(payload, DEMO_PRODUCER_KEYS[artifact_for(payload).producer])
        for payload in payloads
    ]
    risk = RiskAcceptance(
        "RA-12",
        "R-12",
        candidate_binding(candidate),
        candidate.tenant,
        candidate.environment,
        policy.version,
        "team:agent-security",
        "director:risk",
        "A read-only pilot retains bounded latency risk with an operator fallback.",
        now - timedelta(days=1),
        now + timedelta(days=14),
    )
    risks = [attest_risk(risk, DEMO_HUMAN_KEYS[risk.approver])]
    return gate, candidate, evidence, risks, ActorContext("release:operator", "north")


def demo() -> tuple[ReleaseDecision, DeploymentReceipt, DeploymentReceipt]:
    now = datetime(2026, 9, 20, tzinfo=timezone.utc)
    gate, candidate, evidence, risks, approver = build_scenario(now=now)
    decision = gate.evaluate(candidate, evidence, risks, now=now)
    assert decision.ready
    result = gate.authorize_deployment(
        decision,
        candidate,
        approver,
        authorization_id="DA-7",
        now=now + timedelta(minutes=1),
    )
    assert result.allowed and result.authorization
    ledger = DeploymentLedger(gate)
    first = ledger.consume(
        result.authorization,
        candidate,
        current_policy_version=gate.policy.version,
        now=now + timedelta(minutes=2),
    )
    replay = ledger.consume(
        result.authorization,
        candidate,
        current_policy_version=gate.policy.version,
        now=now + timedelta(minutes=2),
    )
    assert first.allowed and replay.reason == "authorization-replayed"
    return decision, first, replay


if __name__ == "__main__":
    for item in demo():
        print(asdict(item))
