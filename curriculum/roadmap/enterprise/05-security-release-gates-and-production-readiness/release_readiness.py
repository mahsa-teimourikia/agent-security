"""Deterministic release-evidence and progressive-delivery control plane.

The model may summarize evidence or recommend a decision. Only trusted
application code admits exact evidence, applies non-compensable blockers,
authorizes a version-bound release, executes one rollout, and verifies the
result or rollback from authoritative provider state.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
import hmac
import json
import math
from typing import Any, Protocol


class EvidenceKind(str, Enum):
    BUILD_PROVENANCE = "build-provenance"
    UNIT_TEST = "unit-test"
    INTEGRATION_TEST = "integration-test"
    ADVERSARIAL_EVAL = "adversarial-eval"
    SUPPLY_CHAIN = "supply-chain"
    ROLLBACK_DRILL = "rollback-drill"
    OBSERVABILITY = "observability"
    RUNBOOK = "runbook"
    OWNER_APPROVAL = "owner-approval"


class EvidenceResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class Admission(str, Enum):
    ADMITTED = "admitted"
    IDEMPOTENT = "idempotent"
    QUARANTINED = "quarantined"


class GateState(str, Enum):
    READY = "ready"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


class ReleaseState(str, Enum):
    CANDIDATE = "candidate"
    CANARY = "canary"
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled-back"
    OUTCOME_UNKNOWN = "outcome-unknown"
    ROLLBACK_UNKNOWN = "rollback-unknown"


class ProviderStatus(str, Enum):
    ABSENT = "absent"
    CANARY = "canary"
    PROMOTED = "promoted"
    STABLE = "stable"
    UNKNOWN = "unknown"


def canonical(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return canonical(asdict(value))
    if isinstance(value, dict):
        return {str(key): canonical(item) for key, item in sorted(value.items())}
    if isinstance(value, (set, frozenset)):
        items = [canonical(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (tuple, list)):
        return [canonical(item) for item in value]
    return value


def digest(value: Any) -> str:
    encoded = json.dumps(canonical(value), sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


class ProofVerifier(Protocol):
    def verify(self, key_id: str, payload: dict[str, Any], proof: str) -> bool: ...


@dataclass(frozen=True)
class TrustedProducer:
    producer_id: str
    tenant: str
    key_id: str
    allowed_kinds: frozenset[EvidenceKind]
    enabled: bool = True


@dataclass(frozen=True)
class TrustedAuthority:
    key_id: str
    tenant: str
    purpose: str
    enabled: bool = True


@dataclass(frozen=True)
class ReleaseEvidence:
    evidence_id: str
    release_digest: str
    tenant: str
    environment: str
    kind: EvidenceKind
    producer_id: str
    policy_version: str
    issued_at: int
    expires_at: int
    result: EvidenceResult
    checked: int
    passed: int
    severe_failures: int
    owner: str
    source_uri: str
    payload_digest: str
    key_id: str = ""
    proof: str = ""

    @property
    def coverage(self) -> float:
        return self.passed / self.checked if self.checked else 0.0


def evidence_payload(evidence: ReleaseEvidence) -> dict[str, Any]:
    return {key: value for key, value in evidence.__dict__.items() if key != "proof"}


@dataclass(frozen=True)
class AdmissionReceipt:
    status: Admission
    reason: str
    evidence_id: str


@dataclass
class EvidenceStore:
    producers: dict[str, TrustedProducer]
    verifier: ProofVerifier
    evidence: dict[str, ReleaseEvidence] = field(default_factory=dict)
    evidence_digests: dict[str, str] = field(default_factory=dict)
    quarantine: list[AdmissionReceipt] = field(default_factory=list)

    def admit(self, item: ReleaseEvidence, *, now: int) -> AdmissionReceipt:
        producer = self.producers.get(item.producer_id)
        if not producer or not producer.enabled:
            return self._quarantine(item, "producer-not-trusted")
        if item.key_id != producer.key_id:
            return self._quarantine(item, "producer-key-mismatch")
        if item.tenant != producer.tenant:
            return self._quarantine(item, "producer-tenant-mismatch")
        if item.kind not in producer.allowed_kinds:
            return self._quarantine(item, "producer-kind-not-allowed")
        if not self.verifier.verify(item.key_id, evidence_payload(item), item.proof):
            return self._quarantine(item, "invalid-evidence-proof")

        candidate = digest(evidence_payload(item))
        previous = self.evidence_digests.get(item.evidence_id)
        if previous:
            if hmac.compare_digest(previous, candidate):
                return AdmissionReceipt(Admission.IDEMPOTENT, "duplicate-delivery", item.evidence_id)
            return self._quarantine(item, "evidence-id-conflict")

        required = (
            item.evidence_id, item.release_digest, item.tenant, item.environment,
            item.policy_version, item.owner, item.source_uri, item.payload_digest,
        )
        if not all(required) or item.checked < 1 or item.passed < 0 or item.passed > item.checked:
            return self._quarantine(item, "invalid-evidence-fields")
        if item.severe_failures < 0:
            return self._quarantine(item, "invalid-severe-failure-count")
        if item.issued_at > now or item.expires_at <= item.issued_at:
            return self._quarantine(item, "invalid-evidence-time")

        self.evidence[item.evidence_id] = item
        self.evidence_digests[item.evidence_id] = candidate
        return AdmissionReceipt(Admission.ADMITTED, "verified-evidence", item.evidence_id)

    def _quarantine(self, item: ReleaseEvidence, reason: str) -> AdmissionReceipt:
        receipt = AdmissionReceipt(Admission.QUARANTINED, reason, item.evidence_id)
        self.quarantine.append(receipt)
        return receipt


@dataclass(frozen=True)
class EvidenceRequirement:
    kind: EvidenceKind
    max_age: int
    min_coverage: float
    waivable: bool = True


@dataclass(frozen=True)
class RiskException:
    exception_id: str
    release_digest: str
    tenant: str
    environment: str
    blocker_code: str
    owner: str
    approved_by: str
    issued_at: int
    expires_at: int
    key_id: str = ""
    proof: str = ""


def exception_payload(exception: RiskException) -> dict[str, Any]:
    return {key: value for key, value in exception.__dict__.items() if key != "proof"}


@dataclass(frozen=True)
class GateDecision:
    state: GateState
    release_digest: str
    evidence_ids: tuple[str, ...]
    evidence_set_digest: str
    exception_ids: tuple[str, ...]
    exception_set_digest: str
    blockers: tuple[str, ...]
    waived_blockers: tuple[str, ...]
    severe_failures: int
    evidence_coverage: float
    oldest_evidence_age: int
    evaluated_at: int


@dataclass
class ReleaseGate:
    store: EvidenceStore
    verifier: ProofVerifier
    exception_authorities: dict[str, TrustedAuthority]
    requirements: tuple[EvidenceRequirement, ...]

    def evaluate(
        self,
        *,
        release_digest: str,
        tenant: str,
        environment: str,
        policy_version: str,
        now: int,
        exceptions: tuple[RiskException, ...] = (),
    ) -> GateDecision:
        exact = [
            item for item in self.store.evidence.values()
            if item.release_digest == release_digest
            and item.tenant == tenant
            and item.environment == environment
        ]
        exact.sort(key=lambda item: (item.kind.value, item.evidence_id))
        blockers: list[str] = []
        incomplete = False
        severe = sum(item.severe_failures for item in exact)
        if severe:
            blockers.append("severe-failure")

        for item in exact:
            admitted_digest = self.store.evidence_digests.get(item.evidence_id, "")
            current_digest = digest(evidence_payload(item))
            if (
                not hmac.compare_digest(admitted_digest, current_digest)
                or not self.verifier.verify(item.key_id, evidence_payload(item), item.proof)
            ):
                blockers.append(f"tampered:{item.kind.value}")

        required_by_kind = {item.kind: item for item in self.requirements}
        grouped_evidence = {
            kind: [item for item in exact if item.kind is kind]
            for kind in required_by_kind
        }
        for kind, requirement in required_by_kind.items():
            candidates = grouped_evidence[kind]
            if not candidates:
                blockers.append(f"missing:{kind.value}")
                incomplete = True
                continue
            if len(candidates) > 1:
                blockers.append(f"duplicate-kind:{kind.value}")
                continue
            item = candidates[0]
            if item.policy_version != policy_version:
                blockers.append(f"policy-mismatch:{kind.value}")
            if item.expires_at <= now or now - item.issued_at > requirement.max_age:
                blockers.append(f"stale:{kind.value}")
            if item.result is EvidenceResult.INCONCLUSIVE:
                blockers.append(f"inconclusive:{kind.value}")
                incomplete = True
            elif item.result is EvidenceResult.FAIL:
                blockers.append(f"failed:{kind.value}")
            if item.coverage < requirement.min_coverage:
                blockers.append(f"coverage:{kind.value}")

        waived: list[str] = []
        accepted_exceptions: list[RiskException] = []
        for exception in exceptions:
            if not self._valid_exception(exception, release_digest, tenant, environment, now):
                blockers.append(f"invalid-exception:{exception.exception_id}")
                continue
            requirement = self._requirement_for_blocker(exception.blocker_code)
            if exception.blocker_code == "severe-failure" or (requirement and not requirement.waivable):
                blockers.append(f"non-waivable:{exception.blocker_code}")
                continue
            if exception.blocker_code in blockers:
                blockers.remove(exception.blocker_code)
                waived.append(exception.blocker_code)
                accepted_exceptions.append(exception)

        evidence_ids = tuple(item.evidence_id for item in exact)
        total_checked = sum(item.checked for item in exact)
        total_passed = sum(item.passed for item in exact)
        ages = [max(0, now - item.issued_at) for item in exact]
        incomplete_only = all(
            reason.startswith(("missing:", "inconclusive:")) for reason in blockers
        )
        state = (
            GateState.READY if not blockers
            else GateState.INCOMPLETE if incomplete and incomplete_only
            else GateState.BLOCKED
        )
        return GateDecision(
            state=state,
            release_digest=release_digest,
            evidence_ids=evidence_ids,
            evidence_set_digest=digest({item.evidence_id: evidence_payload(item) for item in exact}),
            exception_ids=tuple(sorted(item.exception_id for item in accepted_exceptions)),
            exception_set_digest=digest({
                item.exception_id: exception_payload(item) for item in accepted_exceptions
            }),
            blockers=tuple(sorted(set(blockers))),
            waived_blockers=tuple(sorted(waived)),
            severe_failures=severe,
            evidence_coverage=total_passed / total_checked if total_checked else 0.0,
            oldest_evidence_age=max(ages, default=0),
            evaluated_at=now,
        )

    def _requirement_for_blocker(self, blocker: str) -> EvidenceRequirement | None:
        parts = blocker.split(":", 1)
        if len(parts) != 2:
            return None
        try:
            kind = EvidenceKind(parts[1])
        except ValueError:
            return None
        return next((item for item in self.requirements if item.kind is kind), None)

    def _valid_exception(
        self, exception: RiskException, release_digest: str, tenant: str,
        environment: str, now: int,
    ) -> bool:
        authority = self.exception_authorities.get(exception.key_id)
        return bool(
            authority and authority.enabled and authority.purpose == "risk-exception"
            and authority.tenant == tenant and exception.tenant == tenant
            and exception.release_digest == release_digest
            and exception.environment == environment and exception.owner
            and exception.approved_by and exception.issued_at <= now < exception.expires_at
            and self.verifier.verify(exception.key_id, exception_payload(exception), exception.proof)
        )


@dataclass(frozen=True)
class ReleasePlan:
    plan_id: str
    release_digest: str
    stable_digest: str
    tenant: str
    environment: str
    requested_autonomy: str
    policy_version: str
    evidence_set_digest: str
    exception_set_digest: str
    gate_evaluated_at: int
    canary_percent: int
    max_error_rate: float
    min_safety_rate: float
    max_p95_latency_ms: int
    max_cost_per_task: float
    logical_operation_id: str
    plan_digest: str = ""


def bind_plan(plan: ReleasePlan) -> ReleasePlan:
    payload = {key: value for key, value in plan.__dict__.items() if key != "plan_digest"}
    return ReleasePlan(**payload, plan_digest=digest(payload))


@dataclass(frozen=True)
class ReleaseApproval:
    approval_id: str
    plan_digest: str
    release_digest: str
    tenant: str
    environment: str
    expected_release_version: int
    approved_by: str
    issued_at: int
    expires_at: int
    key_id: str = ""
    proof: str = ""


def approval_payload(approval: ReleaseApproval) -> dict[str, Any]:
    return {key: value for key, value in approval.__dict__.items() if key != "proof"}


@dataclass
class ReleaseRecord:
    release_id: str
    tenant: str
    environment: str
    candidate_digest: str
    stable_digest: str
    state: ReleaseState = ReleaseState.CANDIDATE
    version: int = 1


@dataclass(frozen=True)
class ReleaseActor:
    subject: str
    tenant: str
    roles: frozenset[str]


@dataclass(frozen=True)
class CurrentAuthorizer:
    grants: frozenset[tuple[str, str, str]]

    def allows(self, actor: ReleaseActor, environment: str, autonomy: str) -> bool:
        return (
            actor.tenant, environment, autonomy,
        ) in self.grants and "release-operator" in actor.roles


@dataclass(frozen=True)
class CanaryMetrics:
    checked: int
    severe_failures: int
    error_rate: float
    safety_rate: float
    p95_latency_ms: int
    cost_per_task: float


@dataclass(frozen=True)
class ProviderObservation:
    logical_operation_id: str
    release_digest: str
    status: ProviderStatus


class ProviderUnavailable(RuntimeError):
    pass


class TimeoutAfterCommit(RuntimeError):
    pass


@dataclass
class SyntheticDeploymentProvider:
    observations: dict[str, ProviderObservation] = field(default_factory=dict)
    metrics: dict[str, CanaryMetrics] = field(default_factory=dict)
    unavailable_queries: set[str] = field(default_factory=set)
    timeout_after_commit: set[str] = field(default_factory=set)
    deployment_effects: int = 0
    rollback_effects: int = 0

    def query(self, logical_operation_id: str) -> ProviderObservation:
        if logical_operation_id in self.unavailable_queries:
            raise ProviderUnavailable(logical_operation_id)
        return self.observations.get(
            logical_operation_id,
            ProviderObservation(logical_operation_id, "", ProviderStatus.ABSENT),
        )

    def deploy_canary(self, logical_operation_id: str, release_digest: str) -> None:
        existing = self.observations.get(logical_operation_id)
        if existing:
            if existing.release_digest != release_digest:
                raise ValueError("logical-operation-intent-conflict")
            return
        self.observations[logical_operation_id] = ProviderObservation(
            logical_operation_id, release_digest, ProviderStatus.CANARY,
        )
        self.deployment_effects += 1
        if logical_operation_id in self.timeout_after_commit:
            raise TimeoutAfterCommit(logical_operation_id)

    def promote(self, logical_operation_id: str, release_digest: str) -> None:
        current = self.query(logical_operation_id)
        if current.release_digest != release_digest or current.status is not ProviderStatus.CANARY:
            raise ValueError("canary-not-verifiable")
        self.observations[logical_operation_id] = ProviderObservation(
            logical_operation_id, release_digest, ProviderStatus.PROMOTED,
        )

    def rollback(self, logical_operation_id: str, stable_digest: str) -> None:
        rollback_id = f"{logical_operation_id}:rollback"
        existing = self.observations.get(rollback_id)
        if existing and existing.release_digest != stable_digest:
            raise ValueError("rollback-intent-conflict")
        if not existing:
            self.observations[rollback_id] = ProviderObservation(
                rollback_id, stable_digest, ProviderStatus.STABLE,
            )
            self.rollback_effects += 1


@dataclass(frozen=True)
class RolloutReceipt:
    accepted: bool
    reason: str
    state: ReleaseState
    gate_state: GateState
    deployment_verified: bool
    rollback_verified: bool


@dataclass
class RolloutExecutor:
    gate: ReleaseGate
    verifier: ProofVerifier
    approval_authorities: dict[str, TrustedAuthority]
    current_policy_version: str
    used_approvals: set[str] = field(default_factory=set)

    def execute(
        self,
        record: ReleaseRecord,
        plan: ReleasePlan,
        approval: ReleaseApproval,
        actor: ReleaseActor,
        authorizer: CurrentAuthorizer,
        provider: SyntheticDeploymentProvider,
        *,
        now: int,
        exceptions: tuple[RiskException, ...] = (),
    ) -> RolloutReceipt:
        decision = self.gate.evaluate(
            release_digest=record.candidate_digest, tenant=record.tenant,
            environment=record.environment, policy_version=self.current_policy_version,
            now=now, exceptions=exceptions,
        )
        denied = self._preflight(record, plan, approval, actor, authorizer, decision, now)
        if denied:
            return RolloutReceipt(False, denied, record.state, decision.state, False, False)

        try:
            observation = provider.query(plan.logical_operation_id)
        except ProviderUnavailable:
            record.state = ReleaseState.OUTCOME_UNKNOWN
            return RolloutReceipt(False, "provider-query-unavailable", record.state, decision.state, False, False)
        if observation.status is ProviderStatus.ABSENT:
            self.used_approvals.add(approval.approval_id)
            record.state = ReleaseState.CANARY
            record.version += 1
            try:
                provider.deploy_canary(plan.logical_operation_id, plan.release_digest)
            except TimeoutAfterCommit:
                record.state = ReleaseState.OUTCOME_UNKNOWN
                return RolloutReceipt(True, "canary-outcome-unknown", record.state, decision.state, False, False)
        elif observation.release_digest != plan.release_digest:
            return RolloutReceipt(False, "logical-operation-intent-conflict", record.state, decision.state, False, False)
        elif observation.status is ProviderStatus.PROMOTED:
            record.state = ReleaseState.PROMOTED
            return RolloutReceipt(True, "already-promoted", record.state, decision.state, True, False)

        try:
            verified = provider.query(plan.logical_operation_id)
        except ProviderUnavailable:
            record.state = ReleaseState.OUTCOME_UNKNOWN
            return RolloutReceipt(True, "canary-verification-unavailable", record.state, decision.state, False, False)
        if verified.release_digest != plan.release_digest or verified.status is not ProviderStatus.CANARY:
            record.state = ReleaseState.OUTCOME_UNKNOWN
            return RolloutReceipt(True, "canary-not-verifiable", record.state, decision.state, False, False)

        metrics = provider.metrics.get(plan.release_digest)
        metrics_valid = bool(
            metrics and metrics.checked >= 1 and metrics.severe_failures >= 0
            and math.isfinite(metrics.error_rate) and 0 <= metrics.error_rate <= 1
            and math.isfinite(metrics.safety_rate) and 0 <= metrics.safety_rate <= 1
            and metrics.p95_latency_ms >= 0
            and math.isfinite(metrics.cost_per_task) and metrics.cost_per_task >= 0
        )
        if not metrics_valid:
            return self._rollback(record, plan, provider, decision, "canary-metrics-incomplete")
        assert metrics is not None
        unsafe = (
            metrics.severe_failures > 0 or metrics.error_rate > plan.max_error_rate
            or metrics.safety_rate < plan.min_safety_rate
            or metrics.p95_latency_ms > plan.max_p95_latency_ms
            or metrics.cost_per_task > plan.max_cost_per_task
        )
        if unsafe:
            return self._rollback(record, plan, provider, decision, "canary-threshold-failed")

        provider.promote(plan.logical_operation_id, plan.release_digest)
        final = provider.query(plan.logical_operation_id)
        if final.release_digest != plan.release_digest or final.status is not ProviderStatus.PROMOTED:
            record.state = ReleaseState.OUTCOME_UNKNOWN
            return RolloutReceipt(True, "promotion-not-verifiable", record.state, decision.state, False, False)
        record.stable_digest = plan.release_digest
        record.state = ReleaseState.PROMOTED
        record.version += 1
        return RolloutReceipt(True, "promoted-and-verified", record.state, decision.state, True, False)

    def _preflight(
        self, record: ReleaseRecord, plan: ReleasePlan, approval: ReleaseApproval,
        actor: ReleaseActor, authorizer: CurrentAuthorizer, decision: GateDecision, now: int,
    ) -> str:
        if decision.state is not GateState.READY:
            return f"release-gate-{decision.state.value}"
        if plan.plan_digest != digest({key: value for key, value in plan.__dict__.items() if key != "plan_digest"}):
            return "invalid-plan-digest"
        expected = (
            plan.release_digest == record.candidate_digest
            and plan.stable_digest == record.stable_digest
            and plan.tenant == record.tenant and plan.environment == record.environment
            and plan.policy_version == self.current_policy_version
            and plan.evidence_set_digest == decision.evidence_set_digest
            and plan.exception_set_digest == decision.exception_set_digest
            and 0 <= plan.gate_evaluated_at <= decision.evaluated_at
            and 0 < plan.canary_percent <= 25
            and 0 <= plan.max_error_rate <= 0.02
            and plan.min_safety_rate == 1.0
            and 0 < plan.max_p95_latency_ms <= 500
            and 0 < plan.max_cost_per_task <= 0.10
        )
        if not expected:
            return "plan-context-mismatch"
        authority = self.approval_authorities.get(approval.key_id)
        approval_valid = bool(
            authority and authority.enabled and authority.purpose == "release-approval"
            and authority.tenant == record.tenant
            and approval.plan_digest == plan.plan_digest
            and approval.release_digest == record.candidate_digest
            and approval.tenant == record.tenant and approval.environment == record.environment
            and approval.expected_release_version == record.version
            and approval.approved_by and approval.approved_by != actor.subject
            and approval.issued_at <= now < approval.expires_at
            and approval.approval_id not in self.used_approvals
            and self.verifier.verify(approval.key_id, approval_payload(approval), approval.proof)
        )
        if not approval_valid:
            return "invalid-or-consumed-approval"
        if actor.tenant != record.tenant or not authorizer.allows(
            actor, record.environment, plan.requested_autonomy,
        ):
            return "current-authorization-denied"
        return ""

    def _rollback(
        self, record: ReleaseRecord, plan: ReleasePlan,
        provider: SyntheticDeploymentProvider, decision: GateDecision, reason: str,
    ) -> RolloutReceipt:
        provider.rollback(plan.logical_operation_id, plan.stable_digest)
        rollback_id = f"{plan.logical_operation_id}:rollback"
        try:
            observation = provider.query(rollback_id)
        except ProviderUnavailable:
            record.state = ReleaseState.ROLLBACK_UNKNOWN
            return RolloutReceipt(True, f"{reason}:rollback-unknown", record.state, decision.state, True, False)
        verified = observation.release_digest == plan.stable_digest and observation.status is ProviderStatus.STABLE
        record.state = ReleaseState.ROLLED_BACK if verified else ReleaseState.ROLLBACK_UNKNOWN
        record.version += 1
        return RolloutReceipt(True, reason, record.state, decision.state, True, verified)


@dataclass(frozen=True)
class EvaluationReport:
    valid_cases: int
    attack_cases: int
    boundary_cases: int
    failure_cases: int
    ready_rate: float
    severe_failure_escape_rate: float
    stale_evidence_rejection_rate: float
    rollback_success_rate: float
    duplicate_deployment_effects: int
    false_block_rate: float
