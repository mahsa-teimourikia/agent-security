"""Credential-free reference controls for secure multi-agent delegation.

The orchestration framework may propose a handoff. Trusted application code
authenticates participants, issues an attenuated envelope, authorizes every
use, admits a provenance-bound result, and records a content-free receipt.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from hmac import compare_digest, new as hmac_new
import json
from threading import Lock


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _canonical(value: object) -> str:
    """Return stable JSON for identifiers and integrity tags."""

    def normalize(item: object) -> object:
        if isinstance(item, datetime):
            return item.isoformat()
        if isinstance(item, (frozenset, set)):
            return sorted(normalize(part) for part in item)
        if isinstance(item, tuple):
            return [normalize(part) for part in item]
        if hasattr(item, "__dataclass_fields__"):
            return normalize(asdict(item))
        if isinstance(item, dict):
            return {str(key): normalize(val) for key, val in sorted(item.items())}
        if isinstance(item, list):
            return [normalize(part) for part in item]
        return item

    return json.dumps(normalize(value), separators=(",", ":"), sort_keys=True)


def _digest(value: object) -> str:
    return sha256(_canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class ActorContext:
    """Identity asserted by a trusted workload gateway, never by a model."""

    subject: str
    tenant: str
    workload_id: str
    authenticated: bool = True


@dataclass(frozen=True)
class ParentAuthority:
    subject: str
    tenant: str
    workload_id: str
    scopes: frozenset[str]
    resources: frozenset[str]
    artifact_types: frozenset[str]
    audiences: frozenset[str]
    max_budget: int
    expires_at: datetime
    lineage: tuple[str, ...] = ()
    depth: int = 0


@dataclass(frozen=True)
class DelegationPolicy:
    issuer: str
    version: str
    eligible_workloads: frozenset[tuple[str, str]]
    max_budget: int = 10
    max_ttl: timedelta = timedelta(hours=1)
    max_depth: int = 2
    max_fan_out: int = 3


@dataclass(frozen=True)
class DelegationRequest:
    request_id: str
    child: str
    child_workload_id: str
    tenant: str
    audience: str
    scopes: frozenset[str]
    resources: frozenset[str]
    artifact_types: frozenset[str]
    budget: int
    expires_at: datetime
    depth: int = 1
    parent_envelope_id: str | None = None


@dataclass(frozen=True)
class DelegationEnvelope:
    envelope_id: str
    issuer: str
    parent: str
    parent_workload_id: str
    child: str
    child_workload_id: str
    tenant: str
    audience: str
    scopes: frozenset[str]
    resources: frozenset[str]
    artifact_types: frozenset[str]
    budget: int
    issued_at: datetime
    expires_at: datetime
    policy_version: str
    depth: int
    lineage: tuple[str, ...]
    integrity_tag: str


@dataclass(frozen=True)
class DelegationDecision:
    allowed: bool
    reason: str
    request_id: str
    envelope: DelegationEnvelope | None = None


@dataclass(frozen=True)
class OperationRequest:
    operation_id: str
    attempt_id: str
    operation: str
    resource_id: str
    artifact_type: str


@dataclass(frozen=True)
class ArtifactCandidate:
    """Untrusted child output presented to the application boundary."""

    envelope_id: str
    operation_id: str
    artifact_type: str
    content: str
    producer: str
    tenant: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class Artifact:
    artifact_type: str
    content: str
    producer: str
    tenant: str
    envelope_id: str
    operation_id: str
    evidence_ids: tuple[str, ...]
    digest: str


@dataclass(frozen=True)
class DecisionReceipt:
    event_id: str
    envelope_id: str
    operation_id: str
    attempt_id: str
    parent: str
    parent_workload_id: str
    worker: str
    worker_workload_id: str
    tenant: str
    operation: str
    resource_id: str
    artifact_type: str
    allowed: bool
    reason: str
    policy_version: str
    budget_before: int
    budget_after: int
    artifact_digest: str | None
    observed_at: datetime


@dataclass(frozen=True)
class ExecutionDecision:
    allowed: bool
    reason: str
    receipt: DecisionReceipt
    artifact: Artifact | None = None
    replayed: bool = False


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    expected_allowed: bool
    decision: ExecutionDecision


@dataclass(frozen=True)
class EvaluationReport:
    total_cases: int
    attack_attempts: int
    attack_successes: int
    blocked_attacks: int
    valid_tasks: int
    valid_tasks_blocked: int

    @property
    def attack_success_rate(self) -> float:
        return self.attack_successes / self.attack_attempts if self.attack_attempts else 0.0

    @property
    def blocked_valid_task_rate(self) -> float:
        return self.valid_tasks_blocked / self.valid_tasks if self.valid_tasks else 0.0


class DelegationService:
    """Issue integrity-bound envelopes and atomically allocate parent budgets."""

    def __init__(self, policy: DelegationPolicy, *, signing_key: bytes) -> None:
        if not signing_key:
            raise ValueError("signing_key must not be empty")
        if not policy.issuer or not policy.version:
            raise ValueError("policy issuer and version must not be empty")
        if policy.max_budget <= 0 or policy.max_ttl <= timedelta(0):
            raise ValueError("policy budget and lifetime must be positive")
        if policy.max_depth <= 0 or policy.max_fan_out <= 0:
            raise ValueError("policy depth and fan-out must be positive")
        self.policy = policy
        self._signing_key = signing_key
        self._lock = Lock()
        self._issued_requests: dict[str, tuple[str, DelegationEnvelope]] = {}
        self._allocated_budget: dict[str, int] = {}
        self._fan_out: dict[str, int] = {}

    @staticmethod
    def _parent_key(authority: ParentAuthority) -> str:
        return authority.lineage[-1] if authority.lineage else f"root:{authority.tenant}:{authority.subject}"

    @staticmethod
    def _unsigned(envelope: DelegationEnvelope) -> dict[str, object]:
        payload = asdict(envelope)
        payload.pop("integrity_tag")
        return payload

    def _tag(self, unsigned: object) -> str:
        return hmac_new(self._signing_key, _canonical(unsigned).encode(), sha256).hexdigest()

    def verify(self, envelope: DelegationEnvelope) -> bool:
        return compare_digest(envelope.integrity_tag, self._tag(self._unsigned(envelope)))

    def issue(
        self,
        authority: ParentAuthority,
        identity: ActorContext,
        request: DelegationRequest,
        *,
        now: datetime,
    ) -> DelegationDecision:
        request_fingerprint = _digest({"authority": authority, "request": request})
        if not _aware(now) or not _aware(request.expires_at) or not _aware(authority.expires_at):
            return DelegationDecision(False, "timezone-required", request.request_id)
        if not all(
            (
                request.request_id,
                request.child,
                request.child_workload_id,
                request.tenant,
                request.audience,
                authority.subject,
                authority.tenant,
                authority.workload_id,
                identity.subject,
                identity.tenant,
                identity.workload_id,
            )
        ):
            return DelegationDecision(False, "identity-fields", request.request_id)
        if not identity.authenticated:
            return DelegationDecision(False, "parent-unauthenticated", request.request_id)
        if (identity.subject, identity.tenant, identity.workload_id) != (
            authority.subject,
            authority.tenant,
            authority.workload_id,
        ):
            return DelegationDecision(False, "parent-identity-binding", request.request_id)
        if request.tenant != authority.tenant:
            return DelegationDecision(False, "tenant", request.request_id)
        if (request.child, request.child_workload_id) not in self.policy.eligible_workloads:
            return DelegationDecision(False, "child-ineligible", request.request_id)
        if request.audience not in authority.audiences:
            return DelegationDecision(False, "audience", request.request_id)
        if not request.scopes or not request.scopes <= authority.scopes:
            return DelegationDecision(False, "scope", request.request_id)
        if not request.resources or not request.resources <= authority.resources:
            return DelegationDecision(False, "resource", request.request_id)
        if not request.artifact_types or not request.artifact_types <= authority.artifact_types:
            return DelegationDecision(False, "artifact-contract", request.request_id)
        if request.budget <= 0 or request.budget > min(authority.max_budget, self.policy.max_budget):
            return DelegationDecision(False, "budget", request.request_id)
        if not now < request.expires_at <= min(authority.expires_at, now + self.policy.max_ttl):
            return DelegationDecision(False, "lifetime", request.request_id)
        if request.depth != authority.depth + 1 or request.depth > self.policy.max_depth:
            return DelegationDecision(False, "delegation-depth", request.request_id)
        expected_parent = authority.lineage[-1] if authority.lineage else None
        if request.parent_envelope_id != expected_parent:
            return DelegationDecision(False, "lineage", request.request_id)

        parent_key = self._parent_key(authority)
        with self._lock:
            prior = self._issued_requests.get(request.request_id)
            if prior:
                if prior[0] != request_fingerprint:
                    return DelegationDecision(False, "request-replay-mismatch", request.request_id)
                if prior[1].policy_version != self.policy.version:
                    return DelegationDecision(False, "policy-version", request.request_id)
                return DelegationDecision(True, "idempotent-reissue", request.request_id, prior[1])
            if self._fan_out.get(parent_key, 0) >= self.policy.max_fan_out:
                return DelegationDecision(False, "fan-out", request.request_id)
            allocated = self._allocated_budget.get(parent_key, 0)
            if allocated + request.budget > authority.max_budget:
                return DelegationDecision(False, "aggregate-budget", request.request_id)

            envelope_id = _digest(
                {
                    "issuer": self.policy.issuer,
                    "policy": self.policy.version,
                    "parent": parent_key,
                    "request": request_fingerprint,
                }
            )[:20]
            unsigned = {
                "envelope_id": envelope_id,
                "issuer": self.policy.issuer,
                "parent": authority.subject,
                "parent_workload_id": authority.workload_id,
                "child": request.child,
                "child_workload_id": request.child_workload_id,
                "tenant": request.tenant,
                "audience": request.audience,
                "scopes": request.scopes,
                "resources": request.resources,
                "artifact_types": request.artifact_types,
                "budget": request.budget,
                "issued_at": now,
                "expires_at": request.expires_at,
                "policy_version": self.policy.version,
                "depth": request.depth,
                "lineage": (*authority.lineage, envelope_id),
            }
            envelope = DelegationEnvelope(**unsigned, integrity_tag=self._tag(unsigned))
            self._issued_requests[request.request_id] = (request_fingerprint, envelope)
            self._allocated_budget[parent_key] = allocated + request.budget
            self._fan_out[parent_key] = self._fan_out.get(parent_key, 0) + 1
            return DelegationDecision(True, "issued", request.request_id, envelope)

    def derive_authority(self, envelope: DelegationEnvelope) -> ParentAuthority:
        if not self.verify(envelope):
            raise ValueError("invalid envelope integrity")
        return ParentAuthority(
            subject=envelope.child,
            tenant=envelope.tenant,
            workload_id=envelope.child_workload_id,
            scopes=envelope.scopes,
            resources=envelope.resources,
            artifact_types=envelope.artifact_types,
            audiences=frozenset({envelope.audience}),
            max_budget=envelope.budget,
            expires_at=envelope.expires_at,
            lineage=envelope.lineage,
            depth=envelope.depth,
        )


class RevocationRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._revoked: set[str] = set()

    def revoke(self, envelope_id: str) -> None:
        with self._lock:
            self._revoked.add(envelope_id)

    def any_revoked(self, lineage: tuple[str, ...]) -> bool:
        with self._lock:
            return bool(self._revoked.intersection(lineage))


@dataclass
class WorkerSession:
    envelope: DelegationEnvelope
    service: DelegationService
    revocations: RevocationRegistry
    runtime_audience: str
    max_artifact_bytes: int = 512
    consumed: int = 0
    receipts: list[DecisionReceipt] = field(default_factory=list)
    _terminated_reason: str | None = field(default=None, init=False, repr=False)
    _operations: dict[str, tuple[str, Artifact]] = field(default_factory=dict, init=False, repr=False)
    _attempt_ids: set[str] = field(default_factory=set, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_artifact_bytes <= 0:
            raise ValueError("max_artifact_bytes must be positive")

    def _receipt(
        self,
        identity: ActorContext,
        request: OperationRequest,
        *,
        allowed: bool,
        reason: str,
        before: int,
        artifact: Artifact | None,
        now: datetime,
    ) -> DecisionReceipt:
        material = {
            "envelope": self.envelope.envelope_id,
            "operation": request.operation_id,
            "attempt": request.attempt_id,
            "reason": reason,
            "time": now,
            "sequence": len(self.receipts),
        }
        receipt = DecisionReceipt(
            event_id=_digest(material)[:20],
            envelope_id=self.envelope.envelope_id,
            operation_id=request.operation_id,
            attempt_id=request.attempt_id,
            parent=self.envelope.parent,
            parent_workload_id=self.envelope.parent_workload_id,
            worker=identity.subject,
            worker_workload_id=identity.workload_id,
            tenant=identity.tenant,
            operation=request.operation,
            resource_id=request.resource_id,
            artifact_type=request.artifact_type,
            allowed=allowed,
            reason=reason,
            policy_version=self.service.policy.version,
            budget_before=before,
            budget_after=self.consumed,
            artifact_digest=artifact.digest if artifact else None,
            observed_at=now,
        )
        self.receipts.append(receipt)
        return receipt

    def execute(
        self,
        identity: ActorContext,
        request: OperationRequest,
        candidate: ArtifactCandidate,
        *,
        now: datetime,
    ) -> ExecutionDecision:
        if not _aware(now):
            raise ValueError("now must be timezone-aware")
        logical_digest = _digest({"operation": replace(request, attempt_id=""), "candidate": candidate})
        with self._lock:
            before = self.consumed
            boundary_reason = "authorized"
            if self._terminated_reason:
                boundary_reason = "terminated"
            elif not identity.authenticated:
                boundary_reason = "worker-unauthenticated"
            elif (identity.subject, identity.tenant, identity.workload_id) != (
                self.envelope.child,
                self.envelope.tenant,
                self.envelope.child_workload_id,
            ):
                boundary_reason = "worker-identity-binding"
            elif not self.service.verify(self.envelope):
                boundary_reason = "envelope-integrity"
            elif self.runtime_audience != self.envelope.audience:
                boundary_reason = "audience"
            elif self.service.policy.version != self.envelope.policy_version:
                boundary_reason = "policy-version"
            elif self.revocations.any_revoked(self.envelope.lineage):
                boundary_reason = "revoked-lineage"
            elif now >= self.envelope.expires_at:
                boundary_reason = "expired"

            if boundary_reason != "authorized":
                receipt = self._receipt(
                    identity,
                    request,
                    allowed=False,
                    reason=boundary_reason,
                    before=before,
                    artifact=None,
                    now=now,
                )
                return ExecutionDecision(False, boundary_reason, receipt)

            prior = self._operations.get(request.operation_id)
            if prior:
                if prior[0] != logical_digest:
                    reason, artifact, replayed = "operation-replay-mismatch", None, False
                else:
                    reason, artifact, replayed = "idempotent-replay", prior[1], True
                receipt = self._receipt(
                    identity,
                    request,
                    allowed=artifact is not None,
                    reason=reason,
                    before=before,
                    artifact=artifact,
                    now=now,
                )
                return ExecutionDecision(artifact is not None, reason, receipt, artifact, replayed)

            reason = "authorized"
            if not all(
                (
                    request.operation_id,
                    request.attempt_id,
                    request.operation,
                    request.resource_id,
                    request.artifact_type,
                )
            ):
                reason = "operation-contract"
            elif request.attempt_id in self._attempt_ids:
                reason = "attempt-replay"
            elif request.operation not in self.envelope.scopes:
                reason = "scope"
            elif request.resource_id not in self.envelope.resources:
                reason = "resource"
            elif request.artifact_type not in self.envelope.artifact_types:
                reason = "artifact-contract"
            elif self.consumed >= self.envelope.budget:
                reason = "budget"
            elif (
                candidate.envelope_id != self.envelope.envelope_id
                or candidate.operation_id != request.operation_id
                or candidate.producer != identity.subject
                or candidate.tenant != identity.tenant
                or candidate.artifact_type != request.artifact_type
            ):
                reason = "result-binding"
            elif not candidate.content or len(candidate.content.encode()) > self.max_artifact_bytes:
                reason = "result-size"
            elif (
                not candidate.evidence_ids
                or any(not evidence_id for evidence_id in candidate.evidence_ids)
                or len(set(candidate.evidence_ids)) != len(candidate.evidence_ids)
            ):
                reason = "evidence-contract"

            self._attempt_ids.add(request.attempt_id)
            artifact: Artifact | None = None
            if reason == "authorized":
                material = {
                    "envelope_id": candidate.envelope_id,
                    "operation_id": candidate.operation_id,
                    "artifact_type": candidate.artifact_type,
                    "producer": candidate.producer,
                    "tenant": candidate.tenant,
                    "evidence_ids": candidate.evidence_ids,
                    "content": candidate.content,
                }
                artifact = Artifact(**asdict(candidate), digest=_digest(material))
                self.consumed += 1
                self._operations[request.operation_id] = (logical_digest, artifact)

            receipt = self._receipt(
                identity,
                request,
                allowed=artifact is not None,
                reason=reason,
                before=before,
                artifact=artifact,
                now=now,
            )
            return ExecutionDecision(artifact is not None, reason, receipt, artifact)

    def terminate(self, *, reason: str) -> None:
        if not reason.strip():
            raise ValueError("termination reason must not be empty")
        with self._lock:
            self._terminated_reason = reason


def evaluate_cases(cases: list[EvaluationCase]) -> EvaluationReport:
    attacks = [case for case in cases if not case.expected_allowed]
    valid = [case for case in cases if case.expected_allowed]
    return EvaluationReport(
        total_cases=len(cases),
        attack_attempts=len(attacks),
        attack_successes=sum(case.decision.allowed for case in attacks),
        blocked_attacks=sum(not case.decision.allowed for case in attacks),
        valid_tasks=len(valid),
        valid_tasks_blocked=sum(not case.decision.allowed for case in valid),
    )


def build_scenario(*, now: datetime) -> tuple[
    DelegationService,
    RevocationRegistry,
    ParentAuthority,
    ActorContext,
    ActorContext,
    DelegationRequest,
]:
    policy = DelegationPolicy(
        issuer="delegation-service",
        version="policy-7",
        eligible_workloads=frozenset({("researcher", "spiffe://example.test/agent/researcher")}),
        max_budget=4,
        max_ttl=timedelta(minutes=30),
        max_depth=2,
        max_fan_out=2,
    )
    service = DelegationService(policy, signing_key=b"credential-free-course-key")
    registry = RevocationRegistry()
    authority = ParentAuthority(
        subject="supervisor",
        tenant="north",
        workload_id="spiffe://example.test/agent/supervisor",
        scopes=frozenset({"search", "read"}),
        resources=frozenset({"case:42", "kb:public"}),
        artifact_types=frozenset({"evidence-list", "summary"}),
        audiences=frozenset({"research-runtime"}),
        max_budget=3,
        expires_at=now + timedelta(hours=1),
    )
    parent = ActorContext("supervisor", "north", "spiffe://example.test/agent/supervisor")
    worker = ActorContext("researcher", "north", "spiffe://example.test/agent/researcher")
    request = DelegationRequest(
        request_id="delegate-42",
        child="researcher",
        child_workload_id=worker.workload_id,
        tenant="north",
        audience="research-runtime",
        scopes=frozenset({"search"}),
        resources=frozenset({"case:42"}),
        artifact_types=frozenset({"evidence-list"}),
        budget=2,
        expires_at=now + timedelta(minutes=10),
    )
    return service, registry, authority, parent, worker, request


def candidate_for(
    envelope: DelegationEnvelope,
    request: OperationRequest,
    *,
    content: str = "E-17",
) -> ArtifactCandidate:
    return ArtifactCandidate(
        envelope.envelope_id,
        request.operation_id,
        request.artifact_type,
        content,
        envelope.child,
        envelope.tenant,
        ("source:policy-17#retention",),
    )


def demo() -> tuple[WorkerSession, EvaluationReport]:
    now = datetime(2026, 9, 20, tzinfo=timezone.utc)
    service, registry, authority, parent, worker, request = build_scenario(now=now)
    issued = service.issue(authority, parent, request, now=now)
    assert issued.allowed and issued.envelope
    envelope = issued.envelope
    assert envelope.scopes <= authority.scopes and service.verify(envelope)

    session = WorkerSession(envelope, service, registry, "research-runtime")
    valid_request = OperationRequest("op-1", "attempt-1", "search", "case:42", "evidence-list")
    valid = session.execute(worker, valid_request, candidate_for(envelope, valid_request), now=now)
    assert valid.allowed and valid.artifact

    wider = replace(valid_request, operation_id="op-2", attempt_id="attempt-2", operation="delete")
    blocked = session.execute(worker, wider, candidate_for(envelope, wider), now=now)
    assert not blocked.allowed and blocked.reason == "scope"

    retry = replace(valid_request, attempt_id="attempt-retry")
    replay = session.execute(worker, retry, candidate_for(envelope, retry), now=now)
    assert replay.allowed and replay.replayed and session.consumed == 1

    report = evaluate_cases(
        [
            EvaluationCase("valid search", True, valid),
            EvaluationCase("scope escalation", False, blocked),
        ]
    )
    return session, report


if __name__ == "__main__":
    session, report = demo()
    print({"envelope_id": session.envelope.envelope_id, "policy_version": session.envelope.policy_version})
    print(asdict(report))
    for receipt in session.receipts:
        print(asdict(receipt))
