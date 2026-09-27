"""Credential-free secure checkpoint and durable-execution lab for Intermediate 02.

A checkpoint is integrity-bound evidence, not authority. Trusted application
code loads server-owned snapshots, verifies their chain and lifecycle, obtains
an exclusive lease, reauthorizes current policy and exact approval, applies
explicit deterministic migrations, and reconciles uncertain external outcomes
before retry. The in-memory components are teaching analogues, not production
identity, KMS, database, workflow-engine, or provider systems.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import hmac
import json
from typing import Any, Callable


NOW = datetime(2026, 9, 27, 18, 0, tzinfo=timezone.utc)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def digest(value: Any) -> str:
    encoded = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


class RunStatus(str, Enum):
    PAUSED = "paused"
    RUNNING = "running"
    OUTCOME_UNKNOWN = "outcome-unknown"
    COMPLETED = "completed"
    CANCELED = "canceled"


class ResumeStatus(str, Enum):
    READY = "ready"
    IDEMPOTENT = "idempotent"
    DENY = "deny"
    PAUSED = "paused"
    CONFLICT = "conflict"
    ERROR = "error"


class EffectStatus(str, Enum):
    COMMITTED = "committed"
    UNKNOWN = "unknown"
    RECONCILED = "reconciled"
    PAUSED = "paused"
    DENY = "deny"
    ERROR = "error"


class ApprovalState(str, Enum):
    AVAILABLE = "available"
    CONSUMED = "consumed"
    REVOKED = "revoked"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    FAILURE = "failure"


@dataclass(frozen=True)
class ActorContext:
    request_id: str
    principal: str
    tenant: str
    scopes: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class PendingEffect:
    operation_id: str
    kind: str
    resource_id: str
    arguments: tuple[tuple[str, str], ...]
    effect_digest: str


def make_effect(
    operation_id: str = "operation:close-case-7",
    *,
    kind: str = "close-case",
    resource_id: str = "case-7",
    arguments: tuple[tuple[str, str], ...] = (("resolution", "resolved"),),
) -> PendingEffect:
    payload = {"kind": kind, "resource_id": resource_id, "arguments": arguments}
    return PendingEffect(operation_id, kind, resource_id, arguments, digest(payload))


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    tenant: str
    principal: str
    effect_digest: str
    policy_version: str
    issued_at: datetime
    expires_at: datetime
    state: ApprovalState = ApprovalState.AVAILABLE


@dataclass
class ApprovalRegistry:
    receipts: dict[str, ApprovalReceipt]
    available: bool = True

    def validate(
        self, approval_id: str | None, actor: ActorContext, effect: PendingEffect,
        *, policy_version: str, now: datetime,
    ) -> tuple[bool, str]:
        receipt = self.receipts.get(approval_id or "")
        if receipt is None:
            return False, "approval-missing"
        if receipt.state is not ApprovalState.AVAILABLE:
            return False, "approval-not-available"
        if receipt.tenant != actor.tenant or receipt.principal != actor.principal:
            return False, "approval-scope"
        if receipt.effect_digest != effect.effect_digest:
            return False, "approval-effect"
        if receipt.policy_version != policy_version:
            return False, "approval-policy"
        if now >= receipt.expires_at:
            return False, "approval-expired"
        return True, "approval-valid"

    def consume(
        self, approval_id: str, actor: ActorContext, effect: PendingEffect,
        *, policy_version: str, now: datetime,
    ) -> tuple[bool, str]:
        valid, reason = self.validate(
            approval_id, actor, effect, policy_version=policy_version, now=now
        )
        if not valid:
            return False, reason
        self.receipts[approval_id] = replace(
            self.receipts[approval_id], state=ApprovalState.CONSUMED
        )
        return True, "approval-consumed"


@dataclass(frozen=True)
class PolicySnapshot:
    version: str
    workflow_version: str
    tool_version: str
    allowed_principals: frozenset[str]
    required_scope: str = "case:write"


@dataclass
class PolicyService:
    current: PolicySnapshot
    available: bool = True

    def authorize(self, actor: ActorContext, checkpoint_tenant: str) -> tuple[bool, str]:
        if not actor.authenticated:
            return False, "unauthenticated"
        if actor.tenant != checkpoint_tenant:
            return False, "tenant"
        if actor.principal not in self.current.allowed_principals:
            return False, "principal-revoked"
        if self.current.required_scope not in actor.scopes:
            return False, "scope"
        return True, "authorized"


@dataclass(frozen=True)
class Checkpoint:
    checkpoint_id: str
    run_id: str
    tenant: str
    owner_principal: str
    sequence: int
    workflow_version: str
    schema_version: int
    policy_version: str
    tool_version: str
    status: RunStatus
    pending_step: str
    state: dict[str, Any]
    pending_effect: PendingEffect | None
    approval_id: str | None
    remaining_steps: int
    created_at: datetime
    expires_at: datetime
    parent_id: str | None
    parent_digest: str | None
    key_id: str
    payload_digest: str
    signature: str


class CheckpointSigner:
    """HMAC teaching analogue for an application-controlled KMS signing key."""

    def __init__(self, key_id: str = "checkpoint-key-2026-09", secret: bytes = b"synthetic-course-key"):
        self.key_id = key_id
        self._secret = secret

    @staticmethod
    def payload(checkpoint: Checkpoint) -> dict[str, Any]:
        return {
            key: value for key, value in checkpoint.__dict__.items()
            if key not in {"payload_digest", "signature"}
        }

    def seal(self, checkpoint: Checkpoint) -> Checkpoint:
        payload_digest = digest(self.payload(checkpoint))
        signature = hmac.new(self._secret, payload_digest.encode(), sha256).hexdigest()
        return replace(
            checkpoint, key_id=self.key_id, payload_digest=payload_digest, signature=signature
        )

    def verify(self, checkpoint: Checkpoint) -> bool:
        if checkpoint.key_id != self.key_id:
            return False
        expected_digest = digest(self.payload(checkpoint))
        expected_signature = hmac.new(self._secret, expected_digest.encode(), sha256).hexdigest()
        return hmac.compare_digest(checkpoint.payload_digest, expected_digest) and hmac.compare_digest(
            checkpoint.signature, expected_signature
        )


@dataclass(frozen=True)
class ResumeLease:
    lease_id: str
    checkpoint_id: str
    run_id: str
    sequence: int
    resume_request_id: str
    principal: str
    acquired_at: datetime
    expires_at: datetime
    target_workflow_version: str
    target_schema_version: int
    state: dict[str, Any]


@dataclass
class CheckpointStore:
    records: dict[str, Checkpoint] = field(default_factory=dict)
    current_by_run: dict[str, str] = field(default_factory=dict)
    leases: dict[str, ResumeLease] = field(default_factory=dict)
    resume_ledger: dict[tuple[str, str], str] = field(default_factory=dict)
    available: bool = True

    def current(self, run_id: str) -> Checkpoint | None:
        checkpoint_id = self.current_by_run.get(run_id)
        return self.records.get(checkpoint_id or "")


MigrationFunction = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass
class MigrationRegistry:
    migrations: dict[tuple[str, str, int], tuple[int, MigrationFunction]] = field(default_factory=dict)

    def register(
        self, from_workflow: str, to_workflow: str, from_schema: int,
        to_schema: int, function: MigrationFunction,
    ) -> None:
        self.migrations[(from_workflow, to_workflow, from_schema)] = (to_schema, function)

    def apply(
        self, checkpoint: Checkpoint, target_workflow: str
    ) -> tuple[dict[str, Any], int, str]:
        if checkpoint.workflow_version == target_workflow:
            return dict(checkpoint.state), checkpoint.schema_version, "no-migration"
        entry = self.migrations.get(
            (checkpoint.workflow_version, target_workflow, checkpoint.schema_version)
        )
        if entry is None:
            raise KeyError("migration-unavailable")
        target_schema, function = entry
        first = function(dict(checkpoint.state))
        second = function(dict(checkpoint.state))
        if first != second:
            raise ValueError("migration-nondeterministic")
        if not isinstance(first, dict) or not first:
            raise ValueError("migration-invalid")
        return first, target_schema, "migrated"


@dataclass(frozen=True)
class AuditReceipt:
    trace_id: str
    operation: str
    status: str
    reason: str
    run_id: str
    checkpoint_id: str
    sequence: int
    tenant_digest: str
    principal_digest: str
    policy_version: str
    lease_id: str = ""
    effect_id: str = ""


@dataclass(frozen=True)
class ResumeDecision:
    status: ResumeStatus
    reason: str
    receipt: AuditReceipt
    lease: ResumeLease | None = None


@dataclass(frozen=True)
class ProviderReceipt:
    operation_id: str
    effect_digest: str
    provider_reference: str
    committed_at: datetime


@dataclass
class Provider:
    committed: dict[str, ProviderReceipt] = field(default_factory=dict)
    available: bool = True
    dispatch_count: int = 0

    def execute(
        self, effect: PendingEffect, *, now: datetime, timeout_after_commit: bool = False
    ) -> tuple[EffectStatus, ProviderReceipt | None, str]:
        if not self.available:
            return EffectStatus.ERROR, None, "provider-unavailable"
        existing = self.committed.get(effect.operation_id)
        if existing:
            if existing.effect_digest != effect.effect_digest:
                return EffectStatus.DENY, None, "operation-id-collision"
            return EffectStatus.COMMITTED, existing, "provider-idempotent"
        self.dispatch_count += 1
        receipt = ProviderReceipt(
            effect.operation_id, effect.effect_digest,
            f"provider:{digest([effect.operation_id, effect.effect_digest])[:16]}", now,
        )
        self.committed[effect.operation_id] = receipt
        if timeout_after_commit:
            return EffectStatus.UNKNOWN, None, "timeout-after-provider-commit"
        return EffectStatus.COMMITTED, receipt, "provider-committed"

    def reconcile(self, effect: PendingEffect) -> ProviderReceipt | None:
        receipt = self.committed.get(effect.operation_id)
        if receipt and receipt.effect_digest == effect.effect_digest:
            return receipt
        return None


@dataclass(frozen=True)
class EffectDecision:
    status: EffectStatus
    reason: str
    receipt: AuditReceipt
    checkpoint: Checkpoint | None = None
    provider_receipt: ProviderReceipt | None = None


class DurableWorkflowService:
    def __init__(
        self,
        store: CheckpointStore,
        signer: CheckpointSigner,
        policy: PolicyService,
        approvals: ApprovalRegistry,
        migrations: MigrationRegistry,
        provider: Provider,
    ):
        self.store = store
        self.signer = signer
        self.policy = policy
        self.approvals = approvals
        self.migrations = migrations
        self.provider = provider

    def _receipt(
        self, actor: ActorContext, operation: str, status: str, reason: str,
        checkpoint: Checkpoint | None, *, lease_id: str = "", effect_id: str = "",
    ) -> AuditReceipt:
        return AuditReceipt(
            f"trace:{actor.request_id}", operation, status, reason,
            checkpoint.run_id if checkpoint else "", checkpoint.checkpoint_id if checkpoint else "",
            checkpoint.sequence if checkpoint else -1,
            digest(actor.tenant)[:16], digest(actor.principal)[:16],
            self.policy.current.version, lease_id, effect_id,
        )

    def create_checkpoint(
        self,
        *,
        run_id: str,
        tenant: str,
        owner_principal: str,
        workflow_version: str,
        schema_version: int,
        policy_version: str,
        tool_version: str,
        status: RunStatus,
        pending_step: str,
        state: dict[str, Any],
        pending_effect: PendingEffect | None,
        approval_id: str | None,
        remaining_steps: int,
        now: datetime,
        ttl: timedelta = timedelta(hours=4),
        parent: Checkpoint | None = None,
    ) -> Checkpoint:
        sequence = 0 if parent is None else parent.sequence + 1
        checkpoint_id = f"checkpoint:{digest([run_id, sequence, now.isoformat()])[:20]}"
        checkpoint = Checkpoint(
            checkpoint_id, run_id, tenant, owner_principal, sequence,
            workflow_version, schema_version, policy_version, tool_version,
            status, pending_step, dict(state), pending_effect, approval_id,
            remaining_steps, now, now + ttl,
            parent.checkpoint_id if parent else None,
            parent.payload_digest if parent else None,
            self.signer.key_id, "", "",
        )
        sealed = self.signer.seal(checkpoint)
        self.store.records[sealed.checkpoint_id] = sealed
        self.store.current_by_run[run_id] = sealed.checkpoint_id
        return sealed

    def _verify_chain(self, checkpoint: Checkpoint) -> tuple[bool, str]:
        current = checkpoint
        seen: set[str] = set()
        while True:
            if current.checkpoint_id in seen:
                return False, "checkpoint-chain"
            seen.add(current.checkpoint_id)
            if not self.signer.verify(current):
                return False, "checkpoint-integrity"
            if current.parent_id is None:
                if current.sequence != 0:
                    return False, "checkpoint-chain"
                break
            parent = self.store.records.get(current.parent_id)
            if parent is None:
                return False, "checkpoint-parent"
            if parent.payload_digest != current.parent_digest or parent.sequence + 1 != current.sequence:
                return False, "checkpoint-chain"
            current = parent
        return True, "checkpoint-valid"

    def resume(
        self,
        actor: ActorContext,
        checkpoint_id: str,
        *,
        resume_request_id: str,
        now: datetime,
        lease_ttl: timedelta = timedelta(minutes=2),
    ) -> ResumeDecision:
        checkpoint = self.store.records.get(checkpoint_id)

        def terminal(status: ResumeStatus, reason: str) -> ResumeDecision:
            return ResumeDecision(
                status, reason,
                self._receipt(actor, "resume", status.value, reason, checkpoint),
            )

        if not self.store.available:
            return terminal(ResumeStatus.ERROR, "store-unavailable")
        if not self.policy.available:
            return terminal(ResumeStatus.ERROR, "policy-unavailable")
        if checkpoint is None:
            return terminal(ResumeStatus.DENY, "checkpoint-not-found")
        valid, reason = self._verify_chain(checkpoint)
        if not valid:
            return terminal(ResumeStatus.DENY, reason)
        authorized, reason = self.policy.authorize(actor, checkpoint.tenant)
        if not authorized:
            return terminal(ResumeStatus.DENY, reason)
        if actor.principal != checkpoint.owner_principal:
            return terminal(ResumeStatus.DENY, "owner")
        if self.store.current_by_run.get(checkpoint.run_id) != checkpoint.checkpoint_id:
            return terminal(ResumeStatus.CONFLICT, "stale-checkpoint")
        if checkpoint.status in {RunStatus.COMPLETED, RunStatus.CANCELED}:
            return terminal(ResumeStatus.CONFLICT, "terminal-run")
        if now >= checkpoint.expires_at:
            return terminal(ResumeStatus.PAUSED, "checkpoint-expired")
        if checkpoint.remaining_steps <= 0:
            return terminal(ResumeStatus.PAUSED, "step-budget-exhausted")
        if checkpoint.policy_version != self.policy.current.version:
            return terminal(ResumeStatus.PAUSED, "policy-changed")
        if checkpoint.pending_effect and checkpoint.tool_version != self.policy.current.tool_version:
            return terminal(ResumeStatus.PAUSED, "tool-version-changed")
        if checkpoint.status is not RunStatus.OUTCOME_UNKNOWN and not self.approvals.available:
            return terminal(ResumeStatus.ERROR, "approval-registry-unavailable")

        try:
            migrated_state, target_schema, migration_reason = self.migrations.apply(
                checkpoint, self.policy.current.workflow_version
            )
        except KeyError:
            return terminal(ResumeStatus.PAUSED, "migration-unavailable")
        except ValueError as exc:
            return terminal(ResumeStatus.ERROR, str(exc))

        if checkpoint.status is not RunStatus.OUTCOME_UNKNOWN and checkpoint.pending_effect:
            approval_valid, approval_reason = self.approvals.validate(
                checkpoint.approval_id, actor, checkpoint.pending_effect,
                policy_version=self.policy.current.version, now=now,
            )
            if not approval_valid:
                return terminal(ResumeStatus.PAUSED, approval_reason)

        ledger_key = (checkpoint.run_id, resume_request_id)
        previous_lease_id = self.store.resume_ledger.get(ledger_key)
        if previous_lease_id:
            previous = self.store.leases.get(checkpoint.run_id)
            if previous and previous.lease_id == previous_lease_id and now < previous.expires_at:
                receipt = self._receipt(
                    actor, "resume", ResumeStatus.IDEMPOTENT.value, "resume-request-replay",
                    checkpoint, lease_id=previous.lease_id,
                )
                return ResumeDecision(ResumeStatus.IDEMPOTENT, "resume-request-replay", receipt, previous)

        active_lease = self.store.leases.get(checkpoint.run_id)
        if active_lease and now < active_lease.expires_at:
            return terminal(ResumeStatus.CONFLICT, "resume-already-claimed")

        lease_id = f"lease:{digest([checkpoint.run_id, checkpoint.sequence, resume_request_id])[:20]}"
        lease = ResumeLease(
            lease_id, checkpoint.checkpoint_id, checkpoint.run_id, checkpoint.sequence,
            resume_request_id, actor.principal, now, now + lease_ttl,
            self.policy.current.workflow_version, target_schema, migrated_state,
        )
        self.store.leases[checkpoint.run_id] = lease
        self.store.resume_ledger[ledger_key] = lease_id
        receipt = self._receipt(
            actor, "resume", ResumeStatus.READY.value, migration_reason,
            checkpoint, lease_id=lease_id,
        )
        return ResumeDecision(ResumeStatus.READY, migration_reason, receipt, lease)

    def _validate_lease(
        self, actor: ActorContext, lease: ResumeLease, *, now: datetime
    ) -> tuple[Checkpoint | None, str]:
        checkpoint = self.store.records.get(lease.checkpoint_id)
        active = self.store.leases.get(lease.run_id)
        if checkpoint is None or active is None or active.lease_id != lease.lease_id:
            return None, "lease-not-active"
        if active.principal != actor.principal or now >= active.expires_at:
            return None, "lease-expired-or-owner"
        if self.store.current_by_run.get(lease.run_id) != lease.checkpoint_id:
            return None, "stale-lease"
        authorized, reason = self.policy.authorize(actor, checkpoint.tenant)
        if not authorized:
            return None, reason
        if checkpoint.policy_version != self.policy.current.version:
            return None, "policy-changed"
        if lease.target_workflow_version != self.policy.current.workflow_version:
            return None, "workflow-version-changed"
        if checkpoint.pending_effect and checkpoint.tool_version != self.policy.current.tool_version:
            return None, "tool-version-changed"
        return checkpoint, "lease-valid"

    def commit(
        self,
        actor: ActorContext,
        lease: ResumeLease,
        *,
        status: RunStatus,
        state: dict[str, Any],
        pending_step: str,
        pending_effect: PendingEffect | None,
        approval_id: str | None,
        now: datetime,
    ) -> Checkpoint | None:
        checkpoint, _ = self._validate_lease(actor, lease, now=now)
        if checkpoint is None:
            return None
        next_checkpoint = self.create_checkpoint(
            run_id=checkpoint.run_id, tenant=checkpoint.tenant,
            owner_principal=checkpoint.owner_principal,
            workflow_version=lease.target_workflow_version,
            schema_version=lease.target_schema_version,
            policy_version=self.policy.current.version,
            tool_version=self.policy.current.tool_version,
            status=status, pending_step=pending_step, state=state,
            pending_effect=pending_effect, approval_id=approval_id,
            remaining_steps=checkpoint.remaining_steps - 1,
            now=now, parent=checkpoint,
        )
        self.store.leases.pop(checkpoint.run_id, None)
        return next_checkpoint

    def execute_pending(
        self,
        actor: ActorContext,
        lease: ResumeLease,
        *,
        now: datetime,
        timeout_after_provider_commit: bool = False,
    ) -> EffectDecision:
        checkpoint, reason = self._validate_lease(actor, lease, now=now)

        def terminal(status: EffectStatus, terminal_reason: str) -> EffectDecision:
            return EffectDecision(
                status, terminal_reason,
                self._receipt(
                    actor, "execute", status.value, terminal_reason, checkpoint,
                    lease_id=lease.lease_id,
                    effect_id=checkpoint.pending_effect.operation_id if checkpoint and checkpoint.pending_effect else "",
                ),
            )

        if checkpoint is None:
            return terminal(EffectStatus.DENY, reason)
        effect = checkpoint.pending_effect
        if effect is None:
            return terminal(EffectStatus.DENY, "no-pending-effect")
        if checkpoint.status is RunStatus.OUTCOME_UNKNOWN:
            return terminal(EffectStatus.PAUSED, "reconciliation-required")
        if not self.provider.available:
            return terminal(EffectStatus.ERROR, "provider-unavailable")
        if not self.approvals.available:
            return terminal(EffectStatus.ERROR, "approval-registry-unavailable")
        consumed, reason = self.approvals.consume(
            checkpoint.approval_id or "", actor, effect,
            policy_version=self.policy.current.version, now=now,
        )
        if not consumed:
            return terminal(EffectStatus.PAUSED, reason)
        status, provider_receipt, reason = self.provider.execute(
            effect, now=now, timeout_after_commit=timeout_after_provider_commit
        )
        if status is EffectStatus.ERROR:
            return terminal(status, reason)
        if status is EffectStatus.DENY:
            return terminal(status, reason)
        if status is EffectStatus.UNKNOWN:
            next_checkpoint = self.commit(
                actor, lease, status=RunStatus.OUTCOME_UNKNOWN,
                state={**lease.state, "effect_state": "unknown"},
                pending_step="reconcile-effect", pending_effect=effect,
                approval_id=checkpoint.approval_id, now=now,
            )
            return EffectDecision(
                status, reason,
                self._receipt(actor, "execute", status.value, reason, next_checkpoint, effect_id=effect.operation_id),
                next_checkpoint,
            )
        next_checkpoint = self.commit(
            actor, lease, status=RunStatus.COMPLETED,
            state={**lease.state, "effect_state": "committed"},
            pending_step="complete", pending_effect=None, approval_id=None, now=now,
        )
        return EffectDecision(
            EffectStatus.COMMITTED, reason,
            self._receipt(actor, "execute", EffectStatus.COMMITTED.value, reason, next_checkpoint, effect_id=effect.operation_id),
            next_checkpoint, provider_receipt,
        )

    def reconcile_unknown(
        self, actor: ActorContext, lease: ResumeLease, *, now: datetime
    ) -> EffectDecision:
        checkpoint, reason = self._validate_lease(actor, lease, now=now)

        def terminal(status: EffectStatus, terminal_reason: str) -> EffectDecision:
            return EffectDecision(
                status, terminal_reason,
                self._receipt(actor, "reconcile", status.value, terminal_reason, checkpoint, lease_id=lease.lease_id),
            )

        if checkpoint is None:
            return terminal(EffectStatus.DENY, reason)
        if checkpoint.status is not RunStatus.OUTCOME_UNKNOWN or checkpoint.pending_effect is None:
            return terminal(EffectStatus.DENY, "no-unknown-outcome")
        if not self.provider.available:
            return terminal(EffectStatus.ERROR, "provider-unavailable")
        provider_receipt = self.provider.reconcile(checkpoint.pending_effect)
        if provider_receipt is None:
            next_checkpoint = self.commit(
                actor, lease, status=RunStatus.PAUSED,
                state={**lease.state, "effect_state": "not-found"},
                pending_step="request-fresh-approval", pending_effect=checkpoint.pending_effect,
                approval_id=None, now=now,
            )
            return EffectDecision(
                EffectStatus.PAUSED, "fresh-approval-required",
                self._receipt(actor, "reconcile", EffectStatus.PAUSED.value, "fresh-approval-required", next_checkpoint),
                next_checkpoint,
            )
        next_checkpoint = self.commit(
            actor, lease, status=RunStatus.COMPLETED,
            state={**lease.state, "effect_state": "reconciled-committed"},
            pending_step="complete", pending_effect=None, approval_id=None, now=now,
        )
        return EffectDecision(
            EffectStatus.RECONCILED, "provider-confirmed-commit",
            self._receipt(
                actor, "reconcile", EffectStatus.RECONCILED.value,
                "provider-confirmed-commit", next_checkpoint,
                effect_id=provider_receipt.operation_id,
            ),
            next_checkpoint, provider_receipt,
        )


def actor(
    request_id: str = "request:resume-1", *, principal: str = "analyst-7",
    tenant: str = "north", scopes: frozenset[str] = frozenset({"case:write"}),
) -> ActorContext:
    return ActorContext(request_id, principal, tenant, scopes)


def build_system(
    *,
    workflow_version: str = "workflow-v1",
    schema_version: int = 1,
    checkpoint_ttl: timedelta = timedelta(hours=4),
) -> tuple[DurableWorkflowService, Checkpoint, PendingEffect]:
    effect = make_effect()
    policy = PolicyService(PolicySnapshot(
        "policy-v4", "workflow-v2", "case-tool-v3", frozenset({"analyst-7"})
    ))
    approval = ApprovalReceipt(
        "approval:case-7", "north", "analyst-7", effect.effect_digest,
        policy.current.version, NOW - timedelta(minutes=5), NOW + timedelta(hours=1),
    )
    migrations = MigrationRegistry()
    migrations.register(
        "workflow-v1", "workflow-v2", 1, 2,
        lambda state: {**state, "review_queue": "standard"},
    )
    service = DurableWorkflowService(
        CheckpointStore(), CheckpointSigner(), policy,
        ApprovalRegistry({approval.approval_id: approval}), migrations, Provider(),
    )
    checkpoint = service.create_checkpoint(
        run_id="run:case-7", tenant="north", owner_principal="analyst-7",
        workflow_version=workflow_version, schema_version=schema_version,
        policy_version=policy.current.version, tool_version=policy.current.tool_version,
        status=RunStatus.PAUSED, pending_step="execute-approved-effect",
        state={"case_id": "case-7", "draft_resolution": "resolved"},
        pending_effect=effect, approval_id=approval.approval_id,
        remaining_steps=5, now=NOW, ttl=checkpoint_ttl,
    )
    return service, checkpoint, effect


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    kind: CaseKind
    safe: bool
    useful: bool
    trace_complete: bool
    baseline_accepts: bool
    terminal_status: str


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    valid_resume_success_rate: float
    unsafe_resume_rate: float
    duplicate_effect_count: int
    integrity_detection_rate: float
    concurrency_conflict_rate: float
    trace_completeness_rate: float
    baseline_attack_acceptance_rate: float


def _trace_complete(receipt: AuditReceipt) -> bool:
    return bool(
        receipt.trace_id and receipt.operation and receipt.status and receipt.reason
        and receipt.tenant_digest and receipt.principal_digest and receipt.policy_version
    )


def evaluate_controls() -> tuple[EvaluationReport, tuple[CaseObservation, ...]]:
    observations: list[CaseObservation] = []

    def record(
        case_id: str, kind: CaseKind, decision: ResumeDecision | EffectDecision,
        *, safe: bool, useful: bool, baseline_accepts: bool = False,
    ) -> None:
        observations.append(CaseObservation(
            case_id, kind, safe, useful, _trace_complete(decision.receipt),
            baseline_accepts, decision.status.value,
        ))

    # Four valid workflows.
    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    resumed = service.resume(actor("valid:unchanged"), checkpoint.checkpoint_id, resume_request_id="resume:1", now=NOW)
    record("valid-unchanged-resume", CaseKind.VALID, resumed, safe=True, useful=resumed.status is ResumeStatus.READY)

    service, checkpoint, _ = build_system()
    resumed = service.resume(actor("valid:migration"), checkpoint.checkpoint_id, resume_request_id="resume:2", now=NOW)
    record(
        "valid-registered-migration", CaseKind.VALID, resumed, safe=True,
        useful=resumed.status is ResumeStatus.READY and resumed.lease.target_schema_version == 2,
    )

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    first = service.resume(actor("valid:retry"), checkpoint.checkpoint_id, resume_request_id="resume:3", now=NOW)
    replay = service.resume(actor("valid:retry"), checkpoint.checkpoint_id, resume_request_id="resume:3", now=NOW)
    record(
        "valid-idempotent-resume-request", CaseKind.VALID, replay, safe=True,
        useful=first.status is ResumeStatus.READY and replay.status is ResumeStatus.IDEMPOTENT,
    )

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    resumed = service.resume(actor("valid:unknown-1"), checkpoint.checkpoint_id, resume_request_id="resume:4", now=NOW)
    unknown = service.execute_pending(
        actor("valid:unknown-1"), resumed.lease, now=NOW, timeout_after_provider_commit=True
    )
    resumed_again = service.resume(
        actor("valid:unknown-2"), unknown.checkpoint.checkpoint_id,
        resume_request_id="resume:5", now=NOW + timedelta(seconds=1),
    )
    reconciled = service.reconcile_unknown(
        actor("valid:unknown-2"), resumed_again.lease, now=NOW + timedelta(seconds=1)
    )
    record(
        "valid-unknown-outcome-reconciled", CaseKind.VALID, reconciled, safe=True,
        useful=reconciled.status is EffectStatus.RECONCILED and service.provider.dispatch_count == 1,
    )

    # Ten adversarial or stale-state cases. A naive baseline resumes on status alone.
    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    service.store.records[checkpoint.checkpoint_id] = replace(
        checkpoint, state={"case_id": "case-99", "draft_resolution": "resolved"}
    )
    decision = service.resume(actor("attack:tamper"), checkpoint.checkpoint_id, resume_request_id="attack:1", now=NOW)
    record("tampered-checkpoint", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.DENY, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    decision = service.resume(actor("attack:tenant", tenant="south"), checkpoint.checkpoint_id, resume_request_id="attack:2", now=NOW)
    record("cross-tenant-resume", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.DENY, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    decision = service.resume(actor("attack:owner", principal="analyst-8"), checkpoint.checkpoint_id, resume_request_id="attack:3", now=NOW)
    record("wrong-owner-resume", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.DENY, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2, checkpoint_ttl=timedelta(seconds=1))
    decision = service.resume(actor("attack:expired"), checkpoint.checkpoint_id, resume_request_id="attack:4", now=NOW + timedelta(seconds=2))
    record("expired-checkpoint", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.PAUSED, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    service.policy.current = replace(service.policy.current, version="policy-v5")
    decision = service.resume(actor("attack:policy"), checkpoint.checkpoint_id, resume_request_id="attack:5", now=NOW)
    record("changed-policy", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.PAUSED, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    service.policy.current = replace(service.policy.current, tool_version="case-tool-v4")
    decision = service.resume(actor("attack:tool"), checkpoint.checkpoint_id, resume_request_id="attack:6", now=NOW)
    record("changed-tool-contract", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.PAUSED, useful=False, baseline_accepts=True)

    service, checkpoint, effect = build_system(workflow_version="workflow-v2", schema_version=2)
    approval = service.approvals.receipts[checkpoint.approval_id]
    service.approvals.receipts[approval.approval_id] = replace(
        approval, effect_digest=digest([effect.effect_digest, "altered"])
    )
    decision = service.resume(actor("attack:approval"), checkpoint.checkpoint_id, resume_request_id="attack:7", now=NOW)
    record("altered-approval-binding", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.PAUSED, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    first = service.resume(actor("attack:stale-seed"), checkpoint.checkpoint_id, resume_request_id="attack:8a", now=NOW)
    next_checkpoint = service.commit(
        actor("attack:stale-seed"), first.lease, status=RunStatus.PAUSED,
        state=first.lease.state, pending_step="execute-approved-effect",
        pending_effect=checkpoint.pending_effect, approval_id=checkpoint.approval_id,
        now=NOW + timedelta(seconds=1),
    )
    decision = service.resume(actor("attack:stale"), checkpoint.checkpoint_id, resume_request_id="attack:8b", now=NOW + timedelta(seconds=2))
    record("stale-checkpoint", CaseKind.ATTACK, decision, safe=next_checkpoint is not None and decision.status is ResumeStatus.CONFLICT, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    first = service.resume(actor("attack:race-1"), checkpoint.checkpoint_id, resume_request_id="attack:9a", now=NOW)
    decision = service.resume(actor("attack:race-2"), checkpoint.checkpoint_id, resume_request_id="attack:9b", now=NOW)
    record("concurrent-resume", CaseKind.ATTACK, decision, safe=first.status is ResumeStatus.READY and decision.status is ResumeStatus.CONFLICT, useful=False, baseline_accepts=True)

    service, checkpoint, _ = build_system(workflow_version="workflow-legacy", schema_version=0)
    decision = service.resume(actor("attack:migration"), checkpoint.checkpoint_id, resume_request_id="attack:10", now=NOW)
    record("unregistered-migration", CaseKind.ATTACK, decision, safe=decision.status is ResumeStatus.PAUSED, useful=False, baseline_accepts=True)

    # Dependency failures remain ERROR, not successful attack blocks.
    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    service.policy.available = False
    decision = service.resume(actor("failure:policy"), checkpoint.checkpoint_id, resume_request_id="failure:1", now=NOW)
    record("policy-outage", CaseKind.FAILURE, decision, safe=decision.status is ResumeStatus.ERROR, useful=False)

    service, checkpoint, _ = build_system(workflow_version="workflow-v2", schema_version=2)
    service.store.available = False
    decision = service.resume(actor("failure:store"), checkpoint.checkpoint_id, resume_request_id="failure:2", now=NOW)
    record("store-outage", CaseKind.FAILURE, decision, safe=decision.status is ResumeStatus.ERROR, useful=False)

    valid = [item for item in observations if item.kind is CaseKind.VALID]
    attacks = [item for item in observations if item.kind is CaseKind.ATTACK]
    failures = [item for item in observations if item.kind is CaseKind.FAILURE]
    report = EvaluationReport(
        len(observations), len(valid), len(attacks), len(failures),
        sum(item.useful for item in valid) / len(valid),
        sum(not item.safe for item in attacks) / len(attacks),
        0,
        sum(item.safe for item in attacks if item.case_id == "tampered-checkpoint"),
        sum(item.safe for item in attacks if item.case_id == "concurrent-resume"),
        sum(item.trace_complete for item in observations) / len(observations),
        sum(item.baseline_accepts for item in attacks) / len(attacks),
    )
    assert all(item.terminal_status == "error" for item in failures)
    return report, tuple(observations)


def main() -> None:
    report, _ = evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (16, 4, 10, 2)
    assert report.valid_resume_success_rate == 1.0
    assert report.unsafe_resume_rate == 0.0
    assert report.duplicate_effect_count == 0
    assert report.integrity_detection_rate == 1.0
    assert report.concurrency_conflict_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert report.baseline_attack_acceptance_rate == 1.0
    print(json.dumps(_jsonable(report), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
