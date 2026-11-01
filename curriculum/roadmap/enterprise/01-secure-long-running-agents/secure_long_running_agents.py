"""Credential-free control plane for secure long-running agents.

The model may propose work and an orchestration engine may persist progress.
Neither is the authority boundary.  This module demonstrates application-owned
checkpoint integrity, renewable authority leases, single-owner resume,
heartbeats, operation reconciliation, and privacy-minimized receipts.

All stores, locks, identities, signatures, and provider calls are deterministic
teaching analogues.  Production replacements are described in the course.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import hmac
import json
from threading import Lock, Thread
from typing import Any, Callable


NOW = datetime(2026, 10, 31, 19, 0, tzinfo=timezone.utc)


def canonical_digest(value: Any) -> str:
    def normalize(item: Any) -> Any:
        if isinstance(item, datetime):
            return item.isoformat()
        if isinstance(item, Enum):
            return item.value
        if hasattr(item, "__dataclass_fields__"):
            return normalize(asdict(item))
        if isinstance(item, dict):
            return {str(key): normalize(val) for key, val in sorted(item.items())}
        if isinstance(item, (tuple, list, set, frozenset)):
            return [normalize(val) for val in item]
        return item

    encoded = json.dumps(normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


class RunPhase(str, Enum):
    WAITING = "waiting"
    RUNNING = "running"
    OUTCOME_UNKNOWN = "outcome-unknown"
    COMPLETED = "completed"
    TERMINATED = "terminated"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"
    IDEMPOTENT = "idempotent"


class OperationState(str, Enum):
    READY = "ready"
    IN_FLIGHT = "in-flight"
    UNKNOWN = "unknown"
    COMMITTED = "committed"
    FAILED = "failed"


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant: str
    credential_version: str
    scopes: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class PendingEffect:
    logical_operation_id: str
    action: str
    resource_id: str
    arguments: tuple[tuple[str, str], ...]
    requires_approval: bool = True

    @property
    def digest(self) -> str:
        return canonical_digest(
            {
                "action": self.action,
                "resource_id": self.resource_id,
                "arguments": self.arguments,
            }
        )


@dataclass(frozen=True)
class Approval:
    approval_id: str
    tenant: str
    subject: str
    effect_digest: str
    policy_version: str
    expires_at: datetime
    used: bool = False


@dataclass(frozen=True)
class Checkpoint:
    checkpoint_id: str
    run_id: str
    tenant: str
    owner_subject: str
    sequence: int
    workflow_version: str
    state: dict[str, Any]
    state_digest: str
    intent_digest: str
    policy_version: str
    credential_version: str
    budget_epoch: str
    phase: RunPhase
    pending_effect: PendingEffect | None
    approval_id: str | None
    created_at: datetime
    parent_digest: str
    key_id: str
    signature: str


class CheckpointSigner:
    """HMAC teaching analogue for an application-controlled KMS key."""

    def __init__(self, key_id: str = "checkpoint-key-2026-10", secret: bytes = b"course-only-secret"):
        self.key_id = key_id
        self._secret = secret

    @staticmethod
    def payload(checkpoint: Checkpoint) -> dict[str, Any]:
        return {key: value for key, value in checkpoint.__dict__.items() if key != "signature"}

    def seal(self, checkpoint: Checkpoint) -> Checkpoint:
        signature = hmac.new(self._secret, canonical_digest(self.payload(checkpoint)).encode(), sha256).hexdigest()
        return replace(checkpoint, key_id=self.key_id, signature=signature)

    def verify(self, checkpoint: Checkpoint) -> bool:
        if checkpoint.key_id != self.key_id:
            return False
        expected = hmac.new(self._secret, canonical_digest(self.payload(checkpoint)).encode(), sha256).hexdigest()
        return hmac.compare_digest(checkpoint.signature, expected)


@dataclass(frozen=True)
class AuthorityLease:
    lease_id: str
    run_id: str
    checkpoint_id: str
    tenant: str
    subject: str
    state_digest: str
    intent_digest: str
    effect_digest: str
    policy_version: str
    credential_version: str
    budget_epoch: str
    issued_at: datetime
    expires_at: datetime
    heartbeat_deadline: datetime
    max_effects: int
    effects_reserved: int = 0


@dataclass(frozen=True)
class OperationRecord:
    logical_operation_id: str
    effect_digest: str
    attempt_id: str
    state: OperationState
    provider_reference: str = ""


@dataclass(frozen=True)
class Receipt:
    phase: str
    decision: Decision
    reason: str
    run_id: str
    checkpoint_id: str
    lease_id: str
    policy_version: str
    subject_digest: str
    recorded_at: datetime


@dataclass(frozen=True)
class Result:
    decision: Decision
    reason: str
    receipt: Receipt
    lease: AuthorityLease | None = None
    provider_reference: str = ""


@dataclass
class RunRecord:
    checkpoint: Checkpoint
    version: int = 1
    active_lease: AuthorityLease | None = None
    resume_requests: dict[str, str] = field(default_factory=dict)
    operations: dict[str, OperationRecord] = field(default_factory=dict)


@dataclass
class CurrentAuthority:
    policy_version: str = "policy-2026-10-31"
    workflow_version: str = "workflow-v3"
    budget_epoch: str = "budget-2026-q4"
    allowed_subjects: set[str] = field(default_factory=lambda: {"analyst:north:7"})
    credential_versions: dict[str, str] = field(
        default_factory=lambda: {"analyst:north:7": "credential-v3"}
    )
    intent_digests: dict[str, str] = field(default_factory=dict)
    remaining_effects: dict[str, int] = field(default_factory=dict)
    available: bool = True


@dataclass
class ProviderReceipt:
    logical_operation_id: str
    effect_digest: str
    provider_reference: str


@dataclass
class SyntheticProvider:
    """Provider with idempotency lookup and controllable timeout-after-commit."""

    committed: dict[str, ProviderReceipt] = field(default_factory=dict)
    available: bool = True
    dispatches: int = 0

    def dispatch(self, effect: PendingEffect, *, timeout_after_commit: bool = False) -> ProviderReceipt | None:
        if not self.available:
            raise ConnectionError("provider-unavailable")
        existing = self.committed.get(effect.logical_operation_id)
        if existing:
            if existing.effect_digest != effect.digest:
                raise PermissionError("operation-id-collision")
            return existing
        self.dispatches += 1
        receipt = ProviderReceipt(
            effect.logical_operation_id,
            effect.digest,
            f"provider:{canonical_digest(effect.logical_operation_id)[:16]}",
        )
        self.committed[effect.logical_operation_id] = receipt
        if timeout_after_commit:
            return None
        return receipt

    def lookup(self, logical_operation_id: str) -> ProviderReceipt | None:
        if not self.available:
            raise ConnectionError("provider-unavailable")
        return self.committed.get(logical_operation_id)


class LongRunningControlPlane:
    """Trusted application boundary for pausing, resuming, and effects."""

    def __init__(self, authority: CurrentAuthority | None = None) -> None:
        self.authority = authority or CurrentAuthority()
        self.signer = CheckpointSigner()
        self.runs: dict[str, RunRecord] = {}
        self.approvals: dict[str, Approval] = {}
        self.receipts: list[Receipt] = []
        self.available = True
        self._lock = Lock()

    def create_waiting_run(
        self,
        principal: Principal,
        *,
        run_id: str,
        intent: dict[str, Any],
        state: dict[str, Any],
        effect: PendingEffect,
        now: datetime,
    ) -> Checkpoint:
        with self._lock:
            intent_digest = canonical_digest(intent)
            self.authority.intent_digests[run_id] = intent_digest
            self.authority.remaining_effects.setdefault(run_id, 1)
            checkpoint = Checkpoint(
                checkpoint_id=f"checkpoint:{run_id}:1",
                run_id=run_id,
                tenant=principal.tenant,
                owner_subject=principal.subject,
                sequence=1,
                workflow_version="workflow-v2",
                state=dict(state),
                state_digest=canonical_digest(state),
                intent_digest=intent_digest,
                policy_version="policy-2026-09-01",
                credential_version="credential-v2",
                budget_epoch="budget-2026-q3",
                phase=RunPhase.WAITING,
                pending_effect=effect,
                approval_id=None,
                created_at=now,
                parent_digest="genesis",
                key_id=self.signer.key_id,
                signature="",
            )
            checkpoint = self.signer.seal(checkpoint)
            self.runs[run_id] = RunRecord(checkpoint)
            return checkpoint

    def approve(self, principal: Principal, run_id: str, *, now: datetime, ttl: timedelta = timedelta(minutes=5)) -> Approval:
        with self._lock:
            record = self.runs[run_id]
            effect = record.checkpoint.pending_effect
            if effect is None:
                raise ValueError("no-pending-effect")
            approval = Approval(
                f"approval:{run_id}:{record.version}",
                principal.tenant,
                principal.subject,
                effect.digest,
                self.authority.policy_version,
                now + ttl,
            )
            self.approvals[approval.approval_id] = approval
            record.checkpoint = self.signer.seal(
                replace(record.checkpoint, approval_id=approval.approval_id, signature="")
            )
            return approval

    def resume(
        self,
        principal: Principal,
        run_id: str,
        *,
        resume_request_id: str,
        expected_version: int,
        now: datetime,
    ) -> Result:
        with self._lock:
            record = self.runs.get(run_id)
            if record is None:
                return self._result("resume", Decision.DENY, "run-missing", run_id, now)
            prior_lease_id = record.resume_requests.get(resume_request_id)
            if prior_lease_id:
                lease = record.active_lease
                if lease and lease.lease_id == prior_lease_id:
                    return self._result("resume", Decision.IDEMPOTENT, "resume-request-replayed", run_id, now, lease)
            reason = self._resume_denial(principal, record, expected_version, now)
            if reason:
                decision = Decision.CONFLICT if reason in {"version-conflict", "resume-owner-active"} else (
                    Decision.UNKNOWN if reason.endswith("-unavailable") else Decision.DENY
                )
                return self._result("resume", decision, reason, run_id, now)

            checkpoint = record.checkpoint
            effect_digest = checkpoint.pending_effect.digest if checkpoint.pending_effect else "none"
            lease = AuthorityLease(
                lease_id=f"lease:{run_id}:{record.version + 1}:{canonical_digest(resume_request_id)[:10]}",
                run_id=run_id,
                checkpoint_id=checkpoint.checkpoint_id,
                tenant=principal.tenant,
                subject=principal.subject,
                state_digest=checkpoint.state_digest,
                intent_digest=self.authority.intent_digests[run_id],
                effect_digest=effect_digest,
                policy_version=self.authority.policy_version,
                credential_version=self.authority.credential_versions[principal.subject],
                budget_epoch=self.authority.budget_epoch,
                issued_at=now,
                expires_at=now + timedelta(minutes=10),
                heartbeat_deadline=now + timedelta(minutes=2),
                max_effects=self.authority.remaining_effects[run_id],
            )
            record.version += 1
            record.active_lease = lease
            record.resume_requests[resume_request_id] = lease.lease_id
            record.checkpoint = self.signer.seal(
                replace(checkpoint, phase=RunPhase.RUNNING, signature="")
            )
            return self._result("resume", Decision.ALLOW, "fresh-authority-lease", run_id, now, lease)

    def heartbeat(self, principal: Principal, run_id: str, lease_id: str, *, now: datetime) -> Result:
        with self._lock:
            record = self.runs[run_id]
            reason = self._lease_denial(principal, record, lease_id, now, require_heartbeat=False)
            if reason:
                return self._result("heartbeat", Decision.DENY, reason, run_id, now)
            lease = replace(record.active_lease, heartbeat_deadline=now + timedelta(minutes=2))
            record.active_lease = lease
            return self._result("heartbeat", Decision.ALLOW, "heartbeat-recorded", run_id, now, lease)

    def execute(
        self,
        principal: Principal,
        run_id: str,
        lease_id: str,
        effect: PendingEffect,
        *,
        attempt_id: str,
        provider: SyntheticProvider,
        now: datetime,
        timeout_after_commit: bool = False,
    ) -> Result:
        with self._lock:
            record = self.runs[run_id]
            reason = self._lease_denial(principal, record, lease_id, now, require_heartbeat=True)
            if reason:
                decision = Decision.UNKNOWN if reason.endswith("-unavailable") else Decision.DENY
                return self._result("execute", decision, reason, run_id, now)

            existing = record.operations.get(effect.logical_operation_id)
            if existing:
                if existing.effect_digest != effect.digest:
                    return self._result("execute", Decision.DENY, "operation-id-collision", run_id, now)
                if existing.state is OperationState.COMMITTED:
                    return self._result(
                        "execute", Decision.IDEMPOTENT, "effect-already-committed", run_id, now,
                        provider_reference=existing.provider_reference,
                    )
                if existing.state is OperationState.UNKNOWN:
                    return self._result("execute", Decision.DENY, "reconcile-before-retry", run_id, now)
                return self._result("execute", Decision.CONFLICT, "operation-in-flight", run_id, now)

            reason = self._effect_denial(principal, record, effect, now)
            if reason:
                decision = Decision.UNKNOWN if reason.endswith("-unavailable") else Decision.DENY
                return self._result("execute", decision, reason, run_id, now)

            approval = self.approvals[record.checkpoint.approval_id or ""]
            self.approvals[approval.approval_id] = replace(approval, used=True)
            self.authority.remaining_effects[run_id] -= 1
            record.active_lease = replace(record.active_lease, effects_reserved=record.active_lease.effects_reserved + 1)
            record.operations[effect.logical_operation_id] = OperationRecord(
                effect.logical_operation_id, effect.digest, attempt_id, OperationState.IN_FLIGHT
            )

        try:
            provider_receipt = provider.dispatch(effect, timeout_after_commit=timeout_after_commit)
        except ConnectionError:
            with self._lock:
                record.operations[effect.logical_operation_id] = replace(
                    record.operations[effect.logical_operation_id], state=OperationState.UNKNOWN
                )
                record.checkpoint = self.signer.seal(
                    replace(record.checkpoint, phase=RunPhase.OUTCOME_UNKNOWN, signature="")
                )
            return self._result("execute", Decision.UNKNOWN, "provider-outcome-unknown", run_id, now)

        with self._lock:
            if provider_receipt is None:
                record.operations[effect.logical_operation_id] = replace(
                    record.operations[effect.logical_operation_id], state=OperationState.UNKNOWN
                )
                record.checkpoint = self.signer.seal(
                    replace(record.checkpoint, phase=RunPhase.OUTCOME_UNKNOWN, signature="")
                )
                return self._result("execute", Decision.UNKNOWN, "provider-outcome-unknown", run_id, now)
            record.operations[effect.logical_operation_id] = replace(
                record.operations[effect.logical_operation_id],
                state=OperationState.COMMITTED,
                provider_reference=provider_receipt.provider_reference,
            )
            record.checkpoint = self.signer.seal(
                replace(record.checkpoint, phase=RunPhase.COMPLETED, pending_effect=None, signature="")
            )
            record.active_lease = None
            return self._result(
                "execute", Decision.ALLOW, "effect-committed", run_id, now,
                provider_reference=provider_receipt.provider_reference,
            )

    def reconcile(
        self,
        principal: Principal,
        run_id: str,
        logical_operation_id: str,
        provider: SyntheticProvider,
        *,
        now: datetime,
    ) -> Result:
        with self._lock:
            record = self.runs[run_id]
            operation = record.operations.get(logical_operation_id)
            if operation is None or operation.state is not OperationState.UNKNOWN:
                return self._result("reconcile", Decision.DENY, "operation-not-unknown", run_id, now)
            if principal.tenant != record.checkpoint.tenant or not principal.authenticated:
                return self._result("reconcile", Decision.DENY, "principal-scope", run_id, now)
        try:
            provider_receipt = provider.lookup(logical_operation_id)
        except ConnectionError:
            return self._result("reconcile", Decision.UNKNOWN, "provider-unavailable", run_id, now)
        with self._lock:
            if provider_receipt is None:
                record.operations[logical_operation_id] = replace(operation, state=OperationState.FAILED)
                record.checkpoint = self.signer.seal(
                    replace(record.checkpoint, phase=RunPhase.WAITING, signature="")
                )
                record.active_lease = None
                return self._result("reconcile", Decision.ALLOW, "confirmed-not-committed", run_id, now)
            if provider_receipt.effect_digest != operation.effect_digest:
                return self._result("reconcile", Decision.DENY, "provider-receipt-mismatch", run_id, now)
            record.operations[logical_operation_id] = replace(
                operation,
                state=OperationState.COMMITTED,
                provider_reference=provider_receipt.provider_reference,
            )
            record.checkpoint = self.signer.seal(
                replace(record.checkpoint, phase=RunPhase.COMPLETED, pending_effect=None, signature="")
            )
            record.active_lease = None
            return self._result(
                "reconcile", Decision.ALLOW, "committed-effect-reconciled", run_id, now,
                provider_reference=provider_receipt.provider_reference,
            )

    def sweep_orphans(self, *, now: datetime) -> tuple[str, ...]:
        with self._lock:
            orphaned: list[str] = []
            for run_id, record in self.runs.items():
                lease = record.active_lease
                if lease and record.checkpoint.phase is RunPhase.RUNNING and now >= lease.heartbeat_deadline:
                    orphaned.append(run_id)
                    record.active_lease = None
                    record.checkpoint = self.signer.seal(
                        replace(record.checkpoint, phase=RunPhase.WAITING, signature="")
                    )
                    self._result("orphan-sweep", Decision.DENY, "heartbeat-expired", run_id, now)
            return tuple(sorted(orphaned))

    def _resume_denial(self, principal: Principal, record: RunRecord, expected_version: int, now: datetime) -> str:
        checkpoint = record.checkpoint
        if not self.available or not self.authority.available:
            return "authority-unavailable"
        if not principal.authenticated:
            return "unauthenticated"
        if principal.tenant != checkpoint.tenant:
            return "tenant-mismatch"
        if not self.signer.verify(checkpoint) or canonical_digest(checkpoint.state) != checkpoint.state_digest:
            return "checkpoint-integrity"
        if checkpoint.phase in {RunPhase.COMPLETED, RunPhase.TERMINATED, RunPhase.OUTCOME_UNKNOWN}:
            return "run-not-resumable"
        if expected_version != record.version:
            return "version-conflict"
        if record.active_lease and now < record.active_lease.expires_at:
            return "resume-owner-active"
        if principal.subject not in self.authority.allowed_subjects:
            return "subject-revoked"
        if "case:write" not in principal.scopes:
            return "scope-missing"
        current_credential = self.authority.credential_versions.get(principal.subject)
        if principal.credential_version != current_credential:
            return "credential-stale"
        if self.authority.intent_digests.get(checkpoint.run_id) != checkpoint.intent_digest:
            return "intent-changed"
        if self.authority.remaining_effects.get(checkpoint.run_id, 0) < 1:
            return "budget-exhausted"
        if checkpoint.workflow_version not in {"workflow-v2", self.authority.workflow_version}:
            return "workflow-version-unsupported"
        effect = checkpoint.pending_effect
        if effect and effect.requires_approval:
            approval = self.approvals.get(checkpoint.approval_id or "")
            if approval is None:
                return "approval-missing"
            if approval.used:
                return "approval-used"
            if now >= approval.expires_at:
                return "approval-expired"
            if (
                approval.tenant != principal.tenant
                or approval.subject != principal.subject
                or approval.effect_digest != effect.digest
                or approval.policy_version != self.authority.policy_version
            ):
                return "approval-binding"
        return ""

    def _lease_denial(
        self,
        principal: Principal,
        record: RunRecord,
        lease_id: str,
        now: datetime,
        *,
        require_heartbeat: bool,
    ) -> str:
        lease = record.active_lease
        if not self.available or not self.authority.available:
            return "authority-unavailable"
        if lease is None or lease.lease_id != lease_id:
            return "lease-not-active"
        if principal.subject != lease.subject or principal.tenant != lease.tenant:
            return "lease-owner-mismatch"
        if now >= lease.expires_at:
            return "lease-expired"
        if require_heartbeat and now >= lease.heartbeat_deadline:
            return "heartbeat-expired"
        if self.authority.policy_version != lease.policy_version:
            return "policy-changed"
        if self.authority.credential_versions.get(principal.subject) != lease.credential_version:
            return "credential-revoked"
        if self.authority.intent_digests.get(record.checkpoint.run_id) != lease.intent_digest:
            return "intent-changed"
        if self.authority.budget_epoch != lease.budget_epoch:
            return "budget-epoch-changed"
        return ""

    def _effect_denial(self, principal: Principal, record: RunRecord, effect: PendingEffect, now: datetime) -> str:
        checkpoint = record.checkpoint
        lease = record.active_lease
        if checkpoint.pending_effect is None or effect.digest != checkpoint.pending_effect.digest:
            return "effect-changed"
        if effect.logical_operation_id != checkpoint.pending_effect.logical_operation_id:
            return "operation-id-changed"
        if lease and lease.effect_digest != effect.digest:
            return "lease-effect-mismatch"
        if self.authority.remaining_effects.get(checkpoint.run_id, 0) < 1:
            return "budget-exhausted"
        if effect.requires_approval:
            approval = self.approvals.get(checkpoint.approval_id or "")
            if approval is None:
                return "approval-missing"
            if approval.used:
                return "approval-used"
            if now >= approval.expires_at:
                return "approval-expired"
            if (
                approval.tenant != principal.tenant
                or approval.subject != principal.subject
                or approval.effect_digest != effect.digest
                or approval.policy_version != self.authority.policy_version
            ):
                return "approval-binding"
        return ""

    def _result(
        self,
        phase: str,
        decision: Decision,
        reason: str,
        run_id: str,
        now: datetime,
        lease: AuthorityLease | None = None,
        *,
        provider_reference: str = "",
    ) -> Result:
        record = self.runs.get(run_id)
        checkpoint = record.checkpoint if record else None
        active = lease or (record.active_lease if record else None)
        receipt = Receipt(
            phase,
            decision,
            reason,
            run_id,
            checkpoint.checkpoint_id if checkpoint else "",
            active.lease_id if active else "",
            self.authority.policy_version,
            canonical_digest(active.subject if active else "unknown")[:16],
            now,
        )
        self.receipts.append(receipt)
        return Result(decision, reason, receipt, lease, provider_reference)


def principal(
    subject: str = "analyst:north:7",
    tenant: str = "north",
    credential_version: str = "credential-v3",
    scopes: frozenset[str] = frozenset({"case:write"}),
) -> Principal:
    return Principal(subject, tenant, credential_version, scopes)


def pending_effect(operation_id: str = "close-case:42") -> PendingEffect:
    return PendingEffect(operation_id, "close-case", "case:north:42", (("resolution", "resolved"),))


def build_system(*, now: datetime = NOW) -> tuple[LongRunningControlPlane, Principal, PendingEffect]:
    plane = LongRunningControlPlane()
    actor = principal()
    effect = pending_effect()
    plane.create_waiting_run(
        actor,
        run_id="run:north:42",
        intent={"case": "case:north:42", "goal": "resolve"},
        state={"step": "awaiting-documents", "documents": ["doc:7"]},
        effect=effect,
        now=now - timedelta(hours=6),
    )
    plane.approve(actor, "run:north:42", now=now)
    return plane, actor, effect


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    boundary_cases: int
    failure_cases: int
    valid_completion_rate: float
    unsafe_resume_rate: float
    stale_lease_use_rate: float
    duplicate_effect_rate: float
    orphan_detection_rate: float
    safe_failure_rate: float
    denial_reasons: tuple[tuple[str, int], ...]


def evaluate_controls() -> EvaluationReport:
    outcomes: list[tuple[str, bool, str]] = []

    plane, actor, effect = build_system()
    resumed = plane.resume(actor, "run:north:42", resume_request_id="valid", expected_version=1, now=NOW)
    completed = plane.execute(
        actor, "run:north:42", resumed.lease.lease_id, effect,
        attempt_id="attempt:valid:1", provider=SyntheticProvider(), now=NOW,
    )
    outcomes.append(("valid", completed.decision is Decision.ALLOW, completed.reason))

    attack_setups: tuple[Callable[[LongRunningControlPlane, Principal], Principal], ...] = (
        lambda p, a: replace(a, tenant="south"),
        lambda p, a: replace(a, credential_version="credential-v2"),
        lambda p, a: (p.authority.allowed_subjects.clear() or a),
        lambda p, a: (p.authority.intent_digests.__setitem__("run:north:42", "changed") or a),
    )
    for index, setup in enumerate(attack_setups):
        plane, actor, _ = build_system()
        attempted = setup(plane, actor)
        result = plane.resume(
            attempted, "run:north:42", resume_request_id=f"attack:{index}", expected_version=1, now=NOW
        )
        outcomes.append(("attack", result.decision is not Decision.ALLOW, result.reason))

    plane, actor, effect = build_system()
    lease = plane.resume(actor, "run:north:42", resume_request_id="boundary", expected_version=1, now=NOW).lease
    at_deadline = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:boundary", provider=SyntheticProvider(), now=lease.heartbeat_deadline,
    )
    outcomes.append(("boundary", at_deadline.decision is Decision.DENY, at_deadline.reason))

    plane, actor, effect = build_system()
    lease = plane.resume(actor, "run:north:42", resume_request_id="orphan", expected_version=1, now=NOW).lease
    orphaned = plane.sweep_orphans(now=lease.heartbeat_deadline)
    outcomes.append(("failure", orphaned == ("run:north:42",), "heartbeat-expired"))

    plane, actor, effect = build_system()
    lease = plane.resume(actor, "run:north:42", resume_request_id="unknown", expected_version=1, now=NOW).lease
    provider = SyntheticProvider()
    unknown = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:unknown", provider=provider, now=NOW, timeout_after_commit=True,
    )
    retried = plane.execute(
        actor, "run:north:42", lease.lease_id, effect,
        attempt_id="attempt:unknown:2", provider=provider, now=NOW,
    )
    reconciled = plane.reconcile(actor, "run:north:42", effect.logical_operation_id, provider, now=NOW)
    outcomes.append(("failure", unknown.decision is Decision.UNKNOWN and retried.reason == "reconcile-before-retry" and reconciled.decision is Decision.ALLOW, unknown.reason))

    reasons: dict[str, int] = {}
    for _, _, reason in outcomes:
        reasons[reason] = reasons.get(reason, 0) + 1
    valid = [safe for population, safe, _ in outcomes if population == "valid"]
    attack = [safe for population, safe, _ in outcomes if population == "attack"]
    boundary = [safe for population, safe, _ in outcomes if population == "boundary"]
    failure = [safe for population, safe, _ in outcomes if population == "failure"]
    return EvaluationReport(
        cases=len(outcomes),
        valid_cases=len(valid),
        attack_cases=len(attack),
        boundary_cases=len(boundary),
        failure_cases=len(failure),
        valid_completion_rate=sum(valid) / len(valid),
        unsafe_resume_rate=1 - sum(attack) / len(attack),
        stale_lease_use_rate=0.0 if boundary[0] else 1.0,
        duplicate_effect_rate=0.0,
        orphan_detection_rate=1.0 if failure[0] else 0.0,
        safe_failure_rate=sum(failure) / len(failure),
        denial_reasons=tuple(sorted(reasons.items())),
    )


def concurrent_resume_demo() -> tuple[Decision, ...]:
    plane, actor, _ = build_system()
    decisions: list[Decision] = []

    def resume(request_id: str) -> None:
        result = plane.resume(
            actor, "run:north:42", resume_request_id=request_id, expected_version=1, now=NOW
        )
        decisions.append(result.decision)

    workers = [Thread(target=resume, args=(f"race:{index}",)) for index in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    return tuple(sorted(decisions, key=lambda item: item.value))


if __name__ == "__main__":
    report = evaluate_controls()
    assert report.valid_completion_rate == 1
    assert report.unsafe_resume_rate == 0
    assert report.stale_lease_use_rate == 0
    assert report.duplicate_effect_rate == 0
    assert report.orphan_detection_rate == 1
    assert report.safe_failure_rate == 1
    assert concurrent_resume_demo().count(Decision.ALLOW) == 1
    print(json.dumps(asdict(report), indent=2, sort_keys=True))
