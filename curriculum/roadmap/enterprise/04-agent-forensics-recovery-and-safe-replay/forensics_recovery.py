"""Deterministic forensics, recovery, and safe-replay control plane.

The course treats prior agent output as evidence, never current authority.  A
trusted application verifies provenance and chronology, reconciles ambiguous
effects, authorizes an exact recovery plan, reuses stable operation identities,
verifies provider state, and records an explicit terminal state.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
import json
from typing import Any, Protocol


class EventKind(str, Enum):
    CHECKPOINT = "checkpoint"
    POLICY_DECISION = "policy-decision"
    EFFECT_REQUEST = "effect-request"
    EFFECT_RESULT = "effect-result"
    CONTAINMENT = "containment"


class Admission(str, Enum):
    ADMITTED = "admitted"
    IDEMPOTENT = "idempotent"
    QUARANTINED = "quarantined"


class EffectStatus(str, Enum):
    NOT_DISPATCHED = "not-dispatched"
    UNKNOWN = "unknown"
    FAILED = "failed"
    COMMITTED = "committed"
    NOT_FOUND = "not-found"


class ReplayDecision(str, Enum):
    SKIP_COMMITTED = "skip-committed"
    REPLAY_ALLOWED = "replay-allowed"
    RECONCILE_REQUIRED = "reconcile-required"
    REVIEW_REQUIRED = "review-required"
    DENIED = "denied"


class RecoveryState(str, Enum):
    CONTAINED = "contained"
    PLANNED = "planned"
    RECOVERING = "recovering"
    RECOVERY_INCOMPLETE = "recovery-incomplete"
    RECOVERED = "recovered"


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


class SignatureVerifier(Protocol):
    def verify(self, key_id: str, payload: dict[str, Any], signature: str) -> bool: ...


@dataclass(frozen=True)
class TrustedProducer:
    producer_id: str
    tenant: str
    key_id: str
    enabled: bool = True


@dataclass(frozen=True)
class TrustedAuthority:
    key_id: str
    tenant: str
    purpose: str
    enabled: bool = True


@dataclass(frozen=True)
class ForensicEvent:
    event_id: str
    case_id: str
    tenant: str
    producer_id: str
    source_sequence: int
    previous_source_digest: str
    observed_at: int
    received_at: int
    kind: EventKind
    run_id: str
    checkpoint_id: str
    logical_operation_id: str
    attempt_id: str
    payload_digest: str
    key_id: str = ""
    signature: str = ""


def event_payload(event: ForensicEvent) -> dict[str, Any]:
    return {key: value for key, value in event.__dict__.items() if key != "signature"}


def event_digest(event: ForensicEvent) -> str:
    return digest(event_payload(event))


@dataclass(frozen=True)
class AdmissionReceipt:
    status: Admission
    reason: str
    event_id: str


@dataclass
class EvidenceStore:
    producers: dict[str, TrustedProducer]
    verifier: SignatureVerifier
    max_age: int = 600
    max_future_skew: int = 5
    events: dict[str, ForensicEvent] = field(default_factory=dict)
    event_digests: dict[str, str] = field(default_factory=dict)
    source_heads: dict[str, tuple[int, str]] = field(default_factory=dict)
    quarantine: list[AdmissionReceipt] = field(default_factory=list)

    def admit(self, event: ForensicEvent, *, now: int) -> AdmissionReceipt:
        producer = self.producers.get(event.producer_id)
        if not producer or not producer.enabled:
            return self._quarantine(event, "producer-not-trusted")
        if event.key_id != producer.key_id:
            return self._quarantine(event, "producer-key-mismatch")
        if producer.tenant != event.tenant:
            return self._quarantine(event, "producer-tenant-mismatch")
        if not self.verifier.verify(event.key_id, event_payload(event), event.signature):
            return self._quarantine(event, "invalid-event-signature")
        required = (
            event.event_id, event.case_id, event.tenant, event.run_id,
            event.checkpoint_id, event.payload_digest,
        )
        if not all(required) or event.source_sequence < 1:
            return self._quarantine(event, "required-evidence-missing")

        candidate_digest = event_digest(event)
        previous = self.event_digests.get(event.event_id)
        if previous:
            if previous == candidate_digest:
                return AdmissionReceipt(Admission.IDEMPOTENT, "duplicate-delivery", event.event_id)
            return self._quarantine(event, "event-id-conflict")

        if event.received_at > now or event.observed_at > now + self.max_future_skew:
            return self._quarantine(event, "event-from-future")
        if now - event.received_at > self.max_age:
            return self._quarantine(event, "event-too-old")

        head_sequence, head_digest = self.source_heads.get(event.producer_id, (0, "GENESIS"))
        if event.source_sequence < head_sequence + 1:
            return self._quarantine(event, "source-sequence-regression")
        if event.source_sequence > head_sequence + 1:
            return self._quarantine(event, "source-sequence-gap")
        if event.previous_source_digest != head_digest:
            return self._quarantine(event, "source-chain-mismatch")

        self.events[event.event_id] = event
        self.event_digests[event.event_id] = candidate_digest
        self.source_heads[event.producer_id] = (event.source_sequence, candidate_digest)
        return AdmissionReceipt(Admission.ADMITTED, "verified-evidence", event.event_id)

    def _quarantine(self, event: ForensicEvent, reason: str) -> AdmissionReceipt:
        receipt = AdmissionReceipt(Admission.QUARANTINED, reason, event.event_id)
        self.quarantine.append(receipt)
        return receipt


@dataclass(frozen=True)
class ChronologyReport:
    case_id: str
    tenant: str
    ordered_event_ids: tuple[str, ...]
    missing_required_event_ids: tuple[str, ...]
    sequence_gaps: tuple[str, ...]
    tampered_event_ids: tuple[str, ...]
    complete: bool
    chronology_digest: str


@dataclass
class ChronologyAnalyzer:
    store: EvidenceStore

    def analyze(self, *, case_id: str, tenant: str, required_event_ids: tuple[str, ...],
                source_high_watermarks: tuple[tuple[str, int], ...]) -> ChronologyReport:
        case_events = [
            event for event in self.store.events.values()
            if event.case_id == case_id and event.tenant == tenant
        ]
        ordered = sorted(
            case_events,
            key=lambda event: (event.observed_at, event.received_at, event.producer_id,
                               event.source_sequence, event.event_id),
        )
        present_ids = {event.event_id for event in case_events}
        missing = tuple(sorted(set(required_event_ids) - present_ids))

        gaps: list[str] = []
        tampered: set[str] = set()
        by_source: dict[str, list[ForensicEvent]] = {}
        for event in case_events:
            by_source.setdefault(event.producer_id, []).append(event)
            if not self.store.verifier.verify(event.key_id, event_payload(event), event.signature):
                tampered.add(event.event_id)
        for producer_id, high_watermark in source_high_watermarks:
            source_events = sorted(by_source.get(producer_id, []), key=lambda item: item.source_sequence)
            sequence_map = {event.source_sequence: event for event in source_events}
            expected_previous = "GENESIS"
            for sequence in range(1, high_watermark + 1):
                event = sequence_map.get(sequence)
                if event is None:
                    gaps.append(f"{producer_id}:{sequence}")
                    continue
                if event.previous_source_digest != expected_previous:
                    tampered.add(event.event_id)
                expected_previous = event_digest(event)

        ordered_ids = tuple(event.event_id for event in ordered)
        chronology_digest = digest({
            "case_id": case_id,
            "tenant": tenant,
            "ordered_event_ids": ordered_ids,
            "event_digests": tuple((event.event_id, event_digest(event)) for event in ordered),
            "required_event_ids": required_event_ids,
            "source_high_watermarks": source_high_watermarks,
        })
        complete = not missing and not gaps and not tampered and bool(case_events)
        return ChronologyReport(
            case_id, tenant, ordered_ids, missing, tuple(gaps), tuple(sorted(tampered)),
            complete, chronology_digest,
        )


@dataclass(frozen=True)
class EffectIntent:
    logical_operation_id: str
    operation: str
    target: str
    argument_digest: str
    prior_status: EffectStatus
    replayable: bool = True

    @property
    def intent_digest(self) -> str:
        return digest({
            "operation": self.operation,
            "target": self.target,
            "argument_digest": self.argument_digest,
        })


@dataclass(frozen=True)
class CheckpointManifest:
    checkpoint_id: str
    case_id: str
    tenant: str
    run_id: str
    state_digest: str
    code_version: str
    captured_policy_version: str
    chronology_digest: str
    containment_evidence_id: str
    expected_event_ids: tuple[str, ...]
    source_high_watermarks: tuple[tuple[str, int], ...]
    effects: tuple[EffectIntent, ...]
    key_id: str = ""
    signature: str = ""


def checkpoint_payload(checkpoint: CheckpointManifest) -> dict[str, Any]:
    return {key: value for key, value in checkpoint.__dict__.items() if key != "signature"}


@dataclass(frozen=True)
class ProviderObservation:
    logical_operation_id: str
    intent_digest: str
    status: EffectStatus
    final: bool
    resource_digest: str = ""


@dataclass
class SyntheticProvider:
    observations: dict[str, ProviderObservation] = field(default_factory=dict)
    unavailable_ids: set[str] = field(default_factory=set)
    timeout_after_commit_ids: set[str] = field(default_factory=set)
    effect_count: int = 0

    def query(self, logical_operation_id: str) -> ProviderObservation | None:
        if logical_operation_id in self.unavailable_ids:
            return None
        return self.observations.get(
            logical_operation_id,
            ProviderObservation(logical_operation_id, "", EffectStatus.NOT_FOUND, True),
        )

    def execute(self, intent: EffectIntent) -> ProviderObservation:
        existing = self.observations.get(intent.logical_operation_id)
        if existing and existing.status is EffectStatus.COMMITTED:
            if existing.intent_digest != intent.intent_digest:
                raise ValueError("idempotency-intent-conflict")
            return existing
        observation = ProviderObservation(
            intent.logical_operation_id, intent.intent_digest, EffectStatus.COMMITTED,
            True, digest((intent.operation, intent.target))[:16],
        )
        self.observations[intent.logical_operation_id] = observation
        self.effect_count += 1
        if intent.logical_operation_id in self.timeout_after_commit_ids:
            raise TimeoutError("provider-timeout-after-commit")
        return observation


@dataclass(frozen=True)
class ReplayItem:
    intent: EffectIntent
    decision: ReplayDecision
    reason: str


@dataclass(frozen=True)
class RecoveryPlan:
    plan_id: str
    case_id: str
    tenant: str
    checkpoint_digest: str
    chronology_digest: str
    expected_case_version: int
    current_policy_version: str
    items: tuple[ReplayItem, ...]
    issued_at: int
    expires_at: int

    @property
    def plan_digest(self) -> str:
        return digest(self)


@dataclass
class RecoveryCase:
    case_id: str
    tenant: str
    state: RecoveryState
    version: int
    incident_commander: str
    receipts: tuple["RecoveryReceipt", ...] = ()


@dataclass
class RecoveryPlanner:
    verifier: SignatureVerifier
    authorities: dict[str, TrustedAuthority]
    allowed_code_versions: frozenset[str]
    analyzer: ChronologyAnalyzer
    compromised_checkpoints: frozenset[str] = frozenset()

    def plan(self, case: RecoveryCase, checkpoint: CheckpointManifest,
             provider: SyntheticProvider, *,
             current_policy_version: str, now: int) -> RecoveryPlan:
        if case.state not in {
            RecoveryState.CONTAINED, RecoveryState.PLANNED,
            RecoveryState.RECOVERY_INCOMPLETE,
        }:
            raise RuntimeError("case-not-ready-for-recovery-planning")
        report = self.analyzer.analyze(
            case_id=checkpoint.case_id,
            tenant=checkpoint.tenant,
            required_event_ids=checkpoint.expected_event_ids,
            source_high_watermarks=checkpoint.source_high_watermarks,
        )
        self._validate_checkpoint(case, report, checkpoint)
        items = tuple(self._classify(effect, provider) for effect in checkpoint.effects)
        case.state = RecoveryState.PLANNED
        case.version += 1
        return RecoveryPlan(
            f"recovery-plan:{checkpoint.checkpoint_id}", case.case_id, case.tenant,
            digest(checkpoint_payload(checkpoint)), report.chronology_digest, case.version,
            current_policy_version, items, now, now + 60,
        )

    def _validate_checkpoint(self, case: RecoveryCase, report: ChronologyReport,
                             checkpoint: CheckpointManifest) -> None:
        authority = self.authorities.get(checkpoint.key_id)
        if not authority or not authority.enabled or authority.purpose != "checkpoint":
            raise PermissionError("checkpoint-authority-not-trusted")
        if authority.tenant != checkpoint.tenant or case.tenant != checkpoint.tenant:
            raise PermissionError("checkpoint-tenant-mismatch")
        if not self.verifier.verify(checkpoint.key_id, checkpoint_payload(checkpoint), checkpoint.signature):
            raise PermissionError("invalid-checkpoint-signature")
        required = (
            checkpoint.checkpoint_id, checkpoint.case_id, checkpoint.tenant,
            checkpoint.run_id, checkpoint.state_digest, checkpoint.code_version,
            checkpoint.captured_policy_version, checkpoint.chronology_digest,
            checkpoint.containment_evidence_id, checkpoint.expected_event_ids,
            checkpoint.source_high_watermarks, checkpoint.effects,
        )
        if not all(required):
            raise ValueError("checkpoint-manifest-incomplete")
        if checkpoint.checkpoint_id in self.compromised_checkpoints:
            raise PermissionError("checkpoint-compromised")
        if (checkpoint.case_id, checkpoint.tenant) != (report.case_id, report.tenant):
            raise PermissionError("chronology-case-mismatch")
        if not report.complete:
            raise RuntimeError("complete-chronology-required")
        if checkpoint.chronology_digest != report.chronology_digest:
            raise PermissionError("checkpoint-chronology-mismatch")
        if checkpoint.containment_evidence_id not in report.ordered_event_ids:
            raise PermissionError("verified-containment-evidence-required")
        if checkpoint.code_version not in self.allowed_code_versions:
            raise PermissionError("checkpoint-code-version-not-approved")

    @staticmethod
    def _classify(intent: EffectIntent, provider: SyntheticProvider) -> ReplayItem:
        if not intent.logical_operation_id or not intent.argument_digest:
            return ReplayItem(intent, ReplayDecision.DENIED, "effect-identity-incomplete")
        if not intent.replayable:
            return ReplayItem(intent, ReplayDecision.REVIEW_REQUIRED, "non-replayable-operation")
        observed = provider.query(intent.logical_operation_id)
        if observed is None:
            return ReplayItem(intent, ReplayDecision.RECONCILE_REQUIRED, "provider-unavailable")
        if observed.status is EffectStatus.COMMITTED:
            if observed.intent_digest != intent.intent_digest:
                return ReplayItem(intent, ReplayDecision.DENIED, "idempotency-intent-conflict")
            return ReplayItem(intent, ReplayDecision.SKIP_COMMITTED, "provider-already-committed")
        if observed.status is EffectStatus.NOT_FOUND and observed.final:
            if intent.prior_status is EffectStatus.COMMITTED:
                return ReplayItem(intent, ReplayDecision.DENIED, "history-provider-conflict")
            return ReplayItem(intent, ReplayDecision.REPLAY_ALLOWED, "authoritative-absence")
        if observed.status is EffectStatus.FAILED and observed.final:
            return ReplayItem(intent, ReplayDecision.REPLAY_ALLOWED, "provider-final-failure")
        return ReplayItem(intent, ReplayDecision.RECONCILE_REQUIRED, "provider-outcome-not-final")


@dataclass(frozen=True)
class RecoveryApproval:
    approval_id: str
    case_id: str
    tenant: str
    plan_digest: str
    expected_case_version: int
    policy_version: str
    approved_by: str
    issued_at: int
    expires_at: int
    key_id: str = ""
    signature: str = ""


def approval_payload(approval: RecoveryApproval) -> dict[str, Any]:
    return {key: value for key, value in approval.__dict__.items() if key != "signature"}


@dataclass(frozen=True)
class Responder:
    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class RecoveryReceipt:
    logical_operation_id: str
    attempt_id: str
    decision: ReplayDecision
    status: EffectStatus
    verified: bool
    reason: str


@dataclass(frozen=True)
class RecoveryResult:
    accepted: bool
    reason: str
    state: RecoveryState
    receipts: tuple[RecoveryReceipt, ...] = ()


@dataclass
class CurrentAuthorizer:
    allowed: frozenset[tuple[str, str, str]]

    def authorize(self, tenant: str, intent: EffectIntent) -> bool:
        return (tenant, intent.operation, intent.target) in self.allowed


@dataclass
class RecoveryExecutor:
    verifier: SignatureVerifier
    authorities: dict[str, TrustedAuthority]
    current_policy_version: str
    used_approvals: set[str] = field(default_factory=set)

    def execute(self, case: RecoveryCase, plan: RecoveryPlan, approval: RecoveryApproval,
                responder: Responder, provider: SyntheticProvider,
                authorizer: CurrentAuthorizer, *, now: int) -> RecoveryResult:
        denial = self._validate(case, plan, approval, responder, authorizer, now)
        if denial:
            return RecoveryResult(False, denial, case.state)

        self.used_approvals.add(approval.approval_id)
        case.state = RecoveryState.RECOVERING
        case.version += 1
        receipts: list[RecoveryReceipt] = []
        for index, item in enumerate(plan.items, 1):
            intent = item.intent
            attempt_id = f"{plan.plan_id}:attempt:{index}"
            if item.decision is ReplayDecision.SKIP_COMMITTED:
                observation = provider.query(intent.logical_operation_id)
                verified = bool(
                    observation and observation.status is EffectStatus.COMMITTED
                    and observation.intent_digest == intent.intent_digest
                )
                receipts.append(RecoveryReceipt(
                    intent.logical_operation_id, attempt_id, item.decision,
                    EffectStatus.COMMITTED if verified else EffectStatus.UNKNOWN,
                    verified, "existing-commit-verified" if verified else "existing-commit-unverified",
                ))
                continue

            observation = provider.query(intent.logical_operation_id)
            if observation is None:
                receipts.append(RecoveryReceipt(
                    intent.logical_operation_id, attempt_id, item.decision,
                    EffectStatus.UNKNOWN, False, "provider-unavailable-before-dispatch",
                ))
                continue
            if observation.status is EffectStatus.COMMITTED:
                verified = observation.intent_digest == intent.intent_digest
                receipts.append(RecoveryReceipt(
                    intent.logical_operation_id, attempt_id, ReplayDecision.SKIP_COMMITTED,
                    EffectStatus.COMMITTED if verified else EffectStatus.UNKNOWN,
                    verified, "commit-won-race" if verified else "idempotency-intent-conflict",
                ))
                continue
            try:
                provider.execute(intent)
            except TimeoutError:
                receipts.append(RecoveryReceipt(
                    intent.logical_operation_id, attempt_id, item.decision,
                    EffectStatus.UNKNOWN, False, "provider-timeout-after-dispatch",
                ))
                continue
            verified_observation = provider.query(intent.logical_operation_id)
            verified = bool(
                verified_observation and verified_observation.status is EffectStatus.COMMITTED
                and verified_observation.intent_digest == intent.intent_digest
            )
            receipts.append(RecoveryReceipt(
                intent.logical_operation_id, attempt_id, item.decision,
                EffectStatus.COMMITTED if verified else EffectStatus.UNKNOWN,
                verified, "replay-commit-verified" if verified else "replay-postcondition-unverified",
            ))

        case.receipts = tuple(receipts)
        complete = len(receipts) == len(plan.items) and all(receipt.verified for receipt in receipts)
        case.state = RecoveryState.RECOVERED if complete else RecoveryState.RECOVERY_INCOMPLETE
        case.version += 1
        return RecoveryResult(
            True, "recovery-verified" if complete else "recovery-incomplete",
            case.state, tuple(receipts),
        )

    def _validate(self, case: RecoveryCase, plan: RecoveryPlan, approval: RecoveryApproval,
                  responder: Responder, authorizer: CurrentAuthorizer, now: int) -> str:
        authority = self.authorities.get(approval.key_id)
        if not authority or not authority.enabled or authority.purpose != "recovery-approval":
            return "approval-authority-not-trusted"
        if authority.tenant != approval.tenant:
            return "approval-authority-tenant-mismatch"
        if not self.verifier.verify(approval.key_id, approval_payload(approval), approval.signature):
            return "invalid-approval-signature"
        if not responder.authenticated or "recovery_approver" not in responder.roles:
            return "recovery-approver-required"
        if responder.subject != approval.approved_by:
            return "approver-binding-mismatch"
        if responder.subject == case.incident_commander:
            return "recovery-separation-required"
        if len({case.tenant, plan.tenant, approval.tenant, responder.tenant}) != 1:
            return "tenant-mismatch"
        if approval.approval_id in self.used_approvals:
            return "approval-already-used"
        if (approval.case_id, plan.case_id) != (case.case_id, case.case_id):
            return "case-binding-mismatch"
        if case.state is not RecoveryState.PLANNED:
            return "case-not-planned"
        if approval.plan_digest != plan.plan_digest:
            return "plan-binding-mismatch"
        if approval.expected_case_version != case.version or plan.expected_case_version != case.version:
            return "case-version-conflict"
        if approval.policy_version != self.current_policy_version or plan.current_policy_version != self.current_policy_version:
            return "recovery-policy-changed"
        if (approval.issued_at < plan.issued_at or now < plan.issued_at
                or now < approval.issued_at or now >= approval.expires_at
                or now >= plan.expires_at):
            return "recovery-authority-not-current"
        if any(item.decision not in {ReplayDecision.SKIP_COMMITTED, ReplayDecision.REPLAY_ALLOWED}
               for item in plan.items):
            return "unresolved-replay-items"
        if any(item.decision is ReplayDecision.REPLAY_ALLOWED
               and not authorizer.authorize(case.tenant, item.intent) for item in plan.items):
            return "current-authorization-denied"
        return ""


@dataclass(frozen=True)
class EvaluationReport:
    valid_cases: int
    attack_cases: int
    boundary_cases: int
    failure_cases: int
    chronology_completion_rate: float
    tamper_detection_rate: float
    unsafe_replay_rate: float
    duplicate_effect_count: int
    valid_recovery_success_rate: float
    false_block_rate: float
    unknown_outcomes_reconciled_rate: float


def plan_decision_counts(items: tuple[ReplayItem, ...]) -> dict[str, int]:
    return {
        decision.value: sum(item.decision is decision for item in items)
        for decision in ReplayDecision
    }
