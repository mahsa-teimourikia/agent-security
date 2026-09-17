"""Deterministic incident containment, recovery, and safe-replay lab.

The model may surface a signal or propose recovery. Trusted application code
admits evidence, verifies containment, binds independent approval to the exact
plan, restores only narrow capability, and reconciles uncertain side effects.
All fixtures are synthetic; the dataclasses model verified control-plane data,
not production credentials or signatures.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import json
from threading import Lock
from typing import Callable, Optional


class Phase(str, Enum):
    ACTIVE = "active"
    DETECTED = "detected"
    CONTAINED = "contained"
    RECOVERY_PENDING = "recovery_pending"
    RECOVERED = "recovered"


class EffectState(str, Enum):
    RESERVED = "reserved"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"
    FAILED = "failed"


@dataclass(frozen=True)
class ActorContext:
    """Identity and roles established by trusted application middleware."""

    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True

    def has_role(self, role: str, tenant: str) -> bool:
        return self.authenticated and self.tenant == tenant and role in self.roles


@dataclass(frozen=True)
class DetectionSignal:
    signal_id: str
    run_id: str
    tenant: str
    detector_id: str
    severity: str
    evidence_ids: tuple[str, ...]
    observed_at: datetime


@dataclass(frozen=True)
class RevocationReceipt:
    receipt_id: str
    run_id: str
    tenant: str
    requested: frozenset[str]
    confirmed: frozenset[str]
    failed: frozenset[str]
    responder: str
    issuer: str
    observed_at: datetime


@dataclass(frozen=True)
class CheckpointSnapshot:
    checkpoint_id: str
    run_id: str
    tenant: str
    state_digest: str
    policy_version: str
    credential_version: str
    created_at: datetime


@dataclass(frozen=True)
class RecoveryPlan:
    plan_id: str
    run_id: str
    tenant: str
    checkpoint_id: str
    checkpoint_digest: str
    policy_version: str
    credential_version: str
    operation_id: str
    action: str
    target: str
    restore_capabilities: frozenset[str]
    requested_by: str
    created_at: datetime


@dataclass(frozen=True)
class ApprovalReceipt:
    approval_id: str
    plan_digest: str
    run_id: str
    tenant: str
    approver: str
    approver_roles: frozenset[str]
    policy_version: str
    issuer: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class ProviderResult:
    state: EffectState
    provider_reference: Optional[str] = None


@dataclass(frozen=True)
class EffectReceipt:
    operation_id: str
    attempt_id: str
    plan_digest: str
    state: EffectState
    reason: str
    provider_reference: Optional[str]
    observed_at: str


@dataclass(frozen=True)
class Event:
    sequence: int
    kind: str
    reason: str
    actor: str
    correlation_id: str
    phase: str
    policy_version: str
    observed_at: str
    previous_hash: str
    event_hash: str


@dataclass(frozen=True)
class LifecycleDecision:
    allowed: bool
    reason: str
    phase: Phase
    event: Event

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class IncidentEvaluation:
    valid_recovery_rate: float
    attack_block_rate: float
    containment_failure_count: int
    forbidden_effect_count: int
    duplicate_effect_count: int
    trace_completeness_rate: float
    reason_counts: dict[str, int]


@dataclass
class IncidentRun:
    run_id: str
    tenant: str
    policy_version: str
    credential_version: str
    trusted_detectors: frozenset[str] = frozenset({"egress-monitor"})
    trusted_revocation_issuers: frozenset[str] = frozenset({"capability-control"})
    trusted_approval_issuers: frozenset[str] = frozenset({"approval-service"})
    phase: Phase = Phase.ACTIVE
    revoked_capabilities: set[str] = field(default_factory=set)
    events: list[Event] = field(default_factory=list)
    pending_plan: Optional[RecoveryPlan] = None
    consumed_approvals: set[str] = field(default_factory=set)
    effects: dict[str, EffectReceipt] = field(default_factory=dict)
    _seen_signals: set[str] = field(default_factory=set, repr=False)
    _detected_at: Optional[datetime] = field(default=None, repr=False)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def _record(
        self,
        kind: str,
        reason: str,
        actor: str,
        correlation_id: str,
        *,
        now: datetime,
    ) -> Event:
        previous = self.events[-1].event_hash if self.events else "GENESIS"
        values = {
            "run_id": self.run_id,
            "sequence": len(self.events) + 1,
            "kind": kind,
            "reason": reason,
            "actor": actor,
            "correlation_id": correlation_id,
            "phase": self.phase.value,
            "policy_version": self.policy_version,
            "observed_at": now.isoformat(),
            "previous_hash": previous,
        }
        payload = json.dumps(values, sort_keys=True, separators=(",", ":"))
        event = Event(
            values["sequence"],
            kind,
            reason,
            actor,
            correlation_id,
            self.phase.value,
            self.policy_version,
            now.isoformat(),
            previous,
            sha256(payload.encode()).hexdigest(),
        )
        self.events.append(event)
        return event

    def _decision(
        self,
        allowed: bool,
        reason: str,
        kind: str,
        actor: str,
        correlation_id: str,
        *,
        now: datetime,
    ) -> LifecycleDecision:
        event = self._record(kind, reason, actor, correlation_id, now=now)
        return LifecycleDecision(allowed, reason, self.phase, event)

    def detect(self, signal: DetectionSignal, *, now: datetime) -> LifecycleDecision:
        """Admit a versioned signal only from the configured detector boundary."""
        with self._lock:
            reason = "signal-accepted"
            if self.phase is not Phase.ACTIVE:
                reason = "invalid-phase"
            elif signal.signal_id in self._seen_signals:
                reason = "duplicate-signal"
            elif signal.run_id != self.run_id or signal.tenant != self.tenant:
                reason = "signal-scope"
            elif signal.detector_id not in self.trusted_detectors:
                reason = "untrusted-detector"
            elif signal.severity not in {"high", "critical"}:
                reason = "severity-threshold"
            elif not signal.evidence_ids or any(not value.strip() for value in signal.evidence_ids):
                reason = "missing-evidence"
            elif signal.observed_at > now:
                reason = "future-signal"
            if reason == "signal-accepted":
                self._seen_signals.add(signal.signal_id)
                self._detected_at = signal.observed_at
                self.phase = Phase.DETECTED
            return self._decision(
                reason == "signal-accepted",
                reason,
                "detection-decision",
                signal.detector_id,
                signal.signal_id,
                now=now,
            )

    def contain(
        self,
        receipt: RevocationReceipt,
        *,
        responder: ActorContext,
        now: datetime,
    ) -> LifecycleDecision:
        """Move to contained only after every requested revocation is confirmed."""
        with self._lock:
            reason = "containment-confirmed"
            if self.phase is not Phase.DETECTED:
                reason = "invalid-phase"
            elif not responder.has_role("incident-responder", self.tenant):
                reason = "responder-authorization"
            elif receipt.responder != responder.subject:
                reason = "responder-binding"
            elif receipt.run_id != self.run_id or receipt.tenant != self.tenant:
                reason = "revocation-scope"
            elif receipt.issuer not in self.trusted_revocation_issuers:
                reason = "revocation-issuer"
            elif not receipt.requested:
                reason = "empty-revocation"
            elif receipt.confirmed != receipt.requested or receipt.failed:
                reason = "revocation-incomplete"
            elif receipt.observed_at > now:
                reason = "future-revocation"
            elif self._detected_at is not None and receipt.observed_at < self._detected_at:
                reason = "revocation-stale"
            if reason == "containment-confirmed":
                self.revoked_capabilities.update(receipt.confirmed)
                self.phase = Phase.CONTAINED
            return self._decision(
                reason == "containment-confirmed",
                reason,
                "containment-decision",
                responder.subject,
                receipt.receipt_id,
                now=now,
            )

    def propose_recovery(
        self,
        plan: RecoveryPlan,
        checkpoint: CheckpointSnapshot,
        *,
        planner: ActorContext,
        now: datetime,
    ) -> LifecycleDecision:
        with self._lock:
            reason = "recovery-proposed"
            if self.phase is not Phase.CONTAINED:
                reason = "invalid-phase"
            elif not planner.has_role("recovery-planner", self.tenant):
                reason = "planner-authorization"
            elif plan.requested_by != planner.subject:
                reason = "planner-binding"
            elif plan.run_id != self.run_id or plan.tenant != self.tenant:
                reason = "plan-scope"
            elif checkpoint.run_id != self.run_id or checkpoint.tenant != self.tenant:
                reason = "checkpoint-scope"
            elif plan.checkpoint_id != checkpoint.checkpoint_id or plan.checkpoint_digest != checkpoint.state_digest:
                reason = "checkpoint-integrity"
            elif plan.policy_version != checkpoint.policy_version or plan.credential_version != checkpoint.credential_version:
                reason = "checkpoint-version"
            elif checkpoint.policy_version != self.policy_version:
                reason = "policy-stale"
            elif checkpoint.credential_version != self.credential_version:
                reason = "credential-stale"
            elif not plan.operation_id or not plan.action or not plan.target:
                reason = "plan-schema"
            elif not plan.restore_capabilities or not plan.restore_capabilities <= self.revoked_capabilities:
                reason = "capability-restore"
            elif plan.created_at > now or checkpoint.created_at > now:
                reason = "future-plan"
            elif checkpoint.created_at > plan.created_at:
                reason = "checkpoint-time"
            if reason == "recovery-proposed":
                self.pending_plan = plan
                self.phase = Phase.RECOVERY_PENDING
            return self._decision(
                reason == "recovery-proposed",
                reason,
                "recovery-proposal",
                planner.subject,
                plan.plan_id,
                now=now,
            )

    def authorize_recovery(
        self,
        approval: ApprovalReceipt,
        checkpoint: CheckpointSnapshot,
        *,
        now: datetime,
        current_policy_version: str,
        current_credential_version: str,
    ) -> LifecycleDecision:
        """Consume a single-use approval bound to the exact current plan."""
        with self._lock:
            plan = self.pending_plan
            reason = "recovery-authorized"
            if approval.approval_id in self.consumed_approvals:
                reason = "approval-replay"
            elif self.phase is not Phase.RECOVERY_PENDING or plan is None:
                reason = "invalid-phase"
            elif approval.issuer not in self.trusted_approval_issuers:
                reason = "approval-issuer"
            elif approval.run_id != self.run_id or approval.tenant != self.tenant:
                reason = "approval-scope"
            elif "recovery-approver" not in approval.approver_roles or approval.approver == plan.requested_by:
                reason = "approval-independence"
            elif approval.plan_digest != recovery_plan_digest(plan):
                reason = "approval-binding"
            elif approval.issued_at > now or approval.issued_at < plan.created_at or approval.expires_at <= now:
                reason = "approval-time"
            elif current_policy_version != self.policy_version:
                reason = "policy-stale"
            elif current_credential_version != self.credential_version:
                reason = "credential-stale"
            elif (
                approval.policy_version != current_policy_version
                or plan.policy_version != current_policy_version
                or checkpoint.policy_version != current_policy_version
            ):
                reason = "policy-stale"
            elif plan.credential_version != current_credential_version or checkpoint.credential_version != current_credential_version:
                reason = "credential-stale"
            elif checkpoint.checkpoint_id != plan.checkpoint_id or checkpoint.state_digest != plan.checkpoint_digest:
                reason = "checkpoint-integrity"
            elif checkpoint.run_id != self.run_id or checkpoint.tenant != self.tenant:
                reason = "checkpoint-scope"
            if reason == "recovery-authorized":
                self.consumed_approvals.add(approval.approval_id)
                self.revoked_capabilities.difference_update(plan.restore_capabilities)
                self.phase = Phase.RECOVERED
            return self._decision(
                reason == "recovery-authorized",
                reason,
                "recovery-decision",
                approval.approver,
                approval.approval_id,
                now=now,
            )

    def execute_effect(
        self,
        *,
        attempt_id: str,
        capability: str,
        now: datetime,
        provider: Callable[[RecoveryPlan], ProviderResult],
    ) -> EffectReceipt:
        """Reserve one logical operation, then preserve any uncertain outcome."""
        with self._lock:
            plan = self.pending_plan
            plan_hash = recovery_plan_digest(plan) if plan else "no-plan"
            operation_id = plan.operation_id if plan else "no-operation"
            prior = self.effects.get(operation_id)
            if self.phase is not Phase.RECOVERED or plan is None:
                return self._blocked_effect(operation_id, attempt_id, plan_hash, "not-recovered", now)
            if capability not in plan.restore_capabilities or capability in self.revoked_capabilities:
                return self._blocked_effect(operation_id, attempt_id, plan_hash, "capability-revoked", now)
            if prior is not None:
                reason = {
                    EffectState.CONFIRMED: "duplicate-confirmed",
                    EffectState.UNKNOWN: "reconcile-required",
                    EffectState.RESERVED: "operation-in-progress",
                    EffectState.FAILED: "terminal-failure",
                }[prior.state]
                return self._blocked_effect(operation_id, attempt_id, plan_hash, reason, now)
            reserved = EffectReceipt(operation_id, attempt_id, plan_hash, EffectState.RESERVED, "reserved", None, now.isoformat())
            self.effects[operation_id] = reserved
            self._record("effect-reserved", "reserved", "application", attempt_id, now=now)

        try:
            provider_result = provider(plan)
        except Exception:
            provider_result = ProviderResult(EffectState.UNKNOWN)

        if not isinstance(provider_result, ProviderResult):
            provider_result = ProviderResult(EffectState.UNKNOWN)

        state = provider_result.state
        if state not in {EffectState.CONFIRMED, EffectState.UNKNOWN, EffectState.FAILED}:
            state = EffectState.UNKNOWN
        if state is EffectState.CONFIRMED and not _valid_provider_reference(provider_result.provider_reference):
            state = EffectState.UNKNOWN
        provider_reference = provider_result.provider_reference if state is EffectState.CONFIRMED else None
        reason = {
            EffectState.CONFIRMED: "provider-confirmed",
            EffectState.UNKNOWN: "outcome-unknown",
            EffectState.FAILED: "provider-failed",
        }[state]
        with self._lock:
            receipt = EffectReceipt(
                operation_id,
                attempt_id,
                plan_hash,
                state,
                reason,
                provider_reference,
                now.isoformat(),
            )
            self.effects[operation_id] = receipt
            self._record("effect-result", reason, "provider-adapter", attempt_id, now=now)
            return receipt

    def _blocked_effect(
        self,
        operation_id: str,
        attempt_id: str,
        plan_hash: str,
        reason: str,
        now: datetime,
    ) -> EffectReceipt:
        receipt = EffectReceipt(operation_id, attempt_id, plan_hash, EffectState.FAILED, reason, None, now.isoformat())
        self._record("effect-blocked", reason, "application", attempt_id, now=now)
        return receipt

    def reconcile_effect(
        self,
        operation_id: str,
        result: ProviderResult,
        *,
        responder: ActorContext,
        now: datetime,
    ) -> LifecycleDecision:
        with self._lock:
            prior = self.effects.get(operation_id)
            reason = "effect-reconciled"
            if not responder.has_role("incident-responder", self.tenant):
                reason = "responder-authorization"
            elif prior is None or prior.state is not EffectState.UNKNOWN:
                reason = "reconciliation-state"
            elif result.state not in {EffectState.CONFIRMED, EffectState.FAILED}:
                reason = "reconciliation-result"
            elif result.state is EffectState.CONFIRMED and not _valid_provider_reference(result.provider_reference):
                reason = "reconciliation-result"
            if reason == "effect-reconciled" and prior is not None:
                self.effects[operation_id] = EffectReceipt(
                    operation_id,
                    prior.attempt_id,
                    prior.plan_digest,
                    result.state,
                    "provider-confirmed" if result.state is EffectState.CONFIRMED else "provider-failed",
                    result.provider_reference,
                    now.isoformat(),
                )
            return self._decision(
                reason == "effect-reconciled",
                reason,
                "effect-reconciliation",
                responder.subject,
                operation_id,
                now=now,
            )

    def verify_event_chain(self) -> bool:
        previous = "GENESIS"
        for expected_sequence, event in enumerate(self.events, start=1):
            values = {
                "run_id": self.run_id,
                "sequence": event.sequence,
                "kind": event.kind,
                "reason": event.reason,
                "actor": event.actor,
                "correlation_id": event.correlation_id,
                "phase": event.phase,
                "policy_version": event.policy_version,
                "observed_at": event.observed_at,
                "previous_hash": previous,
            }
            payload = json.dumps(values, sort_keys=True, separators=(",", ":"))
            if (
                event.sequence != expected_sequence
                or event.previous_hash != previous
                or event.event_hash != sha256(payload.encode()).hexdigest()
            ):
                return False
            previous = event.event_hash
        return True


def checkpoint_digest(state: dict[str, object]) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode()).hexdigest()


def _valid_provider_reference(value: Optional[str]) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 128


def recovery_plan_digest(plan: Optional[RecoveryPlan]) -> str:
    if plan is None:
        return "no-plan"
    values = asdict(plan)
    values["restore_capabilities"] = sorted(plan.restore_capabilities)
    values["created_at"] = plan.created_at.isoformat()
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode()).hexdigest()


def issue_approval(
    plan: RecoveryPlan,
    approver: ActorContext,
    *,
    approval_id: str,
    now: datetime,
    ttl: timedelta = timedelta(minutes=5),
) -> ApprovalReceipt:
    """Synthetic adapter output; production verifies issuer identity/signature."""
    if not approver.has_role("recovery-approver", plan.tenant):
        raise ValueError("approver is not authenticated and authorized for this tenant")
    return ApprovalReceipt(
        approval_id,
        recovery_plan_digest(plan),
        plan.run_id,
        plan.tenant,
        approver.subject,
        approver.roles,
        plan.policy_version,
        "approval-service",
        now,
        now + ttl,
    )


def build_scenario(*, now: datetime) -> tuple[
    IncidentRun,
    ActorContext,
    ActorContext,
    ActorContext,
    DetectionSignal,
    RevocationReceipt,
    CheckpointSnapshot,
    RecoveryPlan,
]:
    responder = ActorContext("operator:lee", "north", frozenset({"incident-responder"}))
    planner = ActorContext("automation:planner", "north", frozenset({"recovery-planner"}))
    approver = ActorContext("operator:sam", "north", frozenset({"recovery-approver"}))
    run = IncidentRun("run-7", "north", "policy-v4", "credential-v2")
    signal = DetectionSignal(
        "signal-7",
        run.run_id,
        run.tenant,
        "egress-monitor",
        "high",
        ("trace-7", "policy-decision-7"),
        now,
    )
    requested = frozenset({"ticket:write", "network:external"})
    revocation = RevocationReceipt(
        "revoke-7",
        run.run_id,
        run.tenant,
        requested,
        requested,
        frozenset(),
        responder.subject,
        "capability-control",
        now,
    )
    state = {"ticket": "T-7", "operation": "close", "version": 4}
    checkpoint = CheckpointSnapshot(
        "checkpoint-4",
        run.run_id,
        run.tenant,
        checkpoint_digest(state),
        run.policy_version,
        run.credential_version,
        now,
    )
    plan = RecoveryPlan(
        "plan-7",
        run.run_id,
        run.tenant,
        checkpoint.checkpoint_id,
        checkpoint.state_digest,
        run.policy_version,
        run.credential_version,
        "effect-T-7-close",
        "close-ticket",
        "ticket:T-7",
        frozenset({"ticket:write"}),
        planner.subject,
        now,
    )
    return run, responder, planner, approver, signal, revocation, checkpoint, plan


def recover_scenario(*, now: datetime) -> tuple[IncidentRun, ActorContext, RecoveryPlan]:
    run, responder, planner, approver, signal, revocation, checkpoint, plan = build_scenario(now=now)
    assert run.detect(signal, now=now)
    assert run.contain(revocation, responder=responder, now=now)
    assert run.propose_recovery(plan, checkpoint, planner=planner, now=now)
    approval = issue_approval(plan, approver, approval_id="approval-7", now=now)
    assert run.authorize_recovery(
        approval,
        checkpoint,
        now=now,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
    )
    return run, responder, plan


def evaluate_incident_controls() -> IncidentEvaluation:
    now = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
    reasons: Counter[str] = Counter()
    traces_complete = 0
    containment_failures = forbidden_effects = duplicates = 0

    valid_run, _, _ = recover_scenario(now=now)
    provider_calls = 0

    def confirmed_provider(_: RecoveryPlan) -> ProviderResult:
        nonlocal provider_calls
        provider_calls += 1
        return ProviderResult(EffectState.CONFIRMED, "provider:T-7")

    valid_effect = valid_run.execute_effect(
        attempt_id="attempt-valid",
        capability="ticket:write",
        now=now,
        provider=confirmed_provider,
    )
    duplicate = valid_run.execute_effect(
        attempt_id="attempt-duplicate",
        capability="ticket:write",
        now=now,
        provider=confirmed_provider,
    )
    valid_successes = int(valid_effect.state is EffectState.CONFIRMED)
    duplicates += max(0, provider_calls - 1)
    reasons.update(event.reason for event in valid_run.events)
    traces_complete += int(valid_run.verify_event_chain())

    attack_results: list[bool] = [duplicate.reason == "duplicate-confirmed" and provider_calls == 1]

    run, _, _, _, _, _, _, _ = build_scenario(now=now)
    evil_signal = DetectionSignal(
        "signal-evil", run.run_id, run.tenant, "model-output", "critical", ("claim-1",), now
    )
    attack_results.append(not bool(run.detect(evil_signal, now=now)))
    reasons.update(event.reason for event in run.events)
    traces_complete += int(run.verify_event_chain())

    run, responder, _, _, signal, revocation, _, _ = build_scenario(now=now)
    assert run.detect(signal, now=now)
    partial = RevocationReceipt(
        revocation.receipt_id,
        revocation.run_id,
        revocation.tenant,
        revocation.requested,
        frozenset({"ticket:write"}),
        frozenset({"network:external"}),
        revocation.responder,
        revocation.issuer,
        now,
    )
    containment = run.contain(partial, responder=responder, now=now)
    containment_failures += int(not containment.allowed)
    attack_results.append(not containment.allowed and run.phase is Phase.DETECTED)
    reasons.update(event.reason for event in run.events)
    traces_complete += int(run.verify_event_chain())

    run, responder, planner, approver, signal, revocation, checkpoint, plan = build_scenario(now=now)
    assert run.detect(signal, now=now)
    assert run.contain(revocation, responder=responder, now=now)
    assert run.propose_recovery(plan, checkpoint, planner=planner, now=now)
    altered_values = asdict(plan)
    altered_values["target"] = "ticket:T-8"
    altered_plan = RecoveryPlan(**altered_values)
    approval = issue_approval(altered_plan, approver, approval_id="approval-altered", now=now)
    denied = run.authorize_recovery(
        approval,
        checkpoint,
        now=now,
        current_policy_version=run.policy_version,
        current_credential_version=run.credential_version,
    )
    attack_results.append(not denied.allowed)
    reasons.update(event.reason for event in run.events)
    traces_complete += int(run.verify_event_chain())

    uncertain_run, _, _ = recover_scenario(now=now)
    unknown = uncertain_run.execute_effect(
        attempt_id="attempt-unknown",
        capability="ticket:write",
        now=now,
        provider=lambda _: ProviderResult(EffectState.UNKNOWN),
    )
    retry = uncertain_run.execute_effect(
        attempt_id="attempt-retry",
        capability="ticket:write",
        now=now,
        provider=lambda _: ProviderResult(EffectState.CONFIRMED, "should-not-run"),
    )
    attack_results.append(unknown.state is EffectState.UNKNOWN and retry.reason == "reconcile-required")
    forbidden_effects += int(retry.provider_reference == "should-not-run")
    duplicates += int(retry.reason == "duplicate-confirmed")
    reasons.update(event.reason for event in uncertain_run.events)
    traces_complete += int(uncertain_run.verify_event_chain())

    return IncidentEvaluation(
        valid_recovery_rate=valid_successes / 1,
        attack_block_rate=sum(attack_results) / len(attack_results),
        containment_failure_count=containment_failures,
        forbidden_effect_count=forbidden_effects,
        duplicate_effect_count=duplicates,
        trace_completeness_rate=traces_complete / 5,
        reason_counts=dict(reasons),
    )


def demo() -> IncidentRun:
    now = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
    run, _, _ = recover_scenario(now=now)
    first = run.execute_effect(
        attempt_id="attempt-1",
        capability="ticket:write",
        now=now,
        provider=lambda _: ProviderResult(EffectState.CONFIRMED, "provider:T-7"),
    )
    duplicate = run.execute_effect(
        attempt_id="attempt-2",
        capability="ticket:write",
        now=now,
        provider=lambda _: ProviderResult(EffectState.CONFIRMED, "duplicate"),
    )
    assert first.state is EffectState.CONFIRMED
    assert duplicate.reason == "duplicate-confirmed" and duplicate.provider_reference is None
    assert "network:external" in run.revoked_capabilities
    assert run.verify_event_chain()
    return run


if __name__ == "__main__":
    for event in demo().events:
        print(asdict(event))
    print(evaluate_incident_controls())
