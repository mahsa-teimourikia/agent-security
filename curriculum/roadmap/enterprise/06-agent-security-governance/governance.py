"""Deterministic governance control plane for Enterprise Course 06.

The module deliberately separates schema parsing, evidence authentication,
governance evaluation, and lifecycle mutation.  It is a teaching control, not
a production GRC system.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
import hashlib
import hmac
import json
from typing import Iterable


def digest(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class RiskTier(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Lifecycle(str, Enum):
    DRAFT = "draft"
    PILOT = "pilot"
    AUTHORIZED = "authorized"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class DecisionState(str, Enum):
    READY = "ready"
    BLOCKED = "blocked"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    tenant: str
    revision: int
    lifecycle: Lifecycle
    business_owner: str
    technical_owner: str
    security_owner: str
    purpose: str
    risk_tier: RiskTier
    environments: tuple[str, ...]
    models: tuple[str, ...]
    tools: tuple[str, ...]
    data_classes: tuple[str, ...]
    effects: tuple[str, ...]
    autonomy: str
    policy_version: str
    control_version: str
    review_due_at: int
    kill_switch_owner: str
    change_digest: str


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    agent_id: str
    tenant: str
    record_revision: int
    kind: str
    producer_id: str
    key_id: str
    policy_version: str
    control_version: str
    created_at: int
    expires_at: int
    passed: int
    checked: int
    severe_failures: int
    proof: str = ""


def evidence_payload(item: Evidence) -> dict:
    return {key: value for key, value in asdict(item).items() if key != "proof"}


@dataclass(frozen=True)
class Producer:
    producer_id: str
    tenant: str
    key_id: str
    allowed_kinds: frozenset[str]


class Keyring:
    """Fixture signer; production systems should use KMS/HSM-backed identity."""

    def __init__(self, keys: dict[str, bytes]):
        self._keys = dict(keys)

    def sign(self, item: Evidence) -> Evidence:
        key = self._keys[item.key_id]
        proof = hmac.new(key, digest(evidence_payload(item)).encode(), hashlib.sha256).hexdigest()
        return replace(item, proof=proof)

    def verify(self, item: Evidence) -> bool:
        try:
            expected = self.sign(replace(item, proof="")).proof
        except KeyError:
            return False
        return hmac.compare_digest(expected, item.proof)


@dataclass(frozen=True)
class AdmissionReceipt:
    admitted: bool
    reason: str
    evidence_digest: str = ""


class EvidenceStore:
    def __init__(self, producers: Iterable[Producer], keyring: Keyring):
        self.producers = {producer.producer_id: producer for producer in producers}
        self.keyring = keyring
        self.items: dict[str, Evidence] = {}
        self.digests: dict[str, str] = {}

    def admit(self, item: Evidence, now: int) -> AdmissionReceipt:
        producer = self.producers.get(item.producer_id)
        if producer is None:
            return AdmissionReceipt(False, "unknown-producer")
        if producer.tenant != item.tenant or producer.key_id != item.key_id:
            return AdmissionReceipt(False, "producer-scope")
        if item.kind not in producer.allowed_kinds:
            return AdmissionReceipt(False, "producer-kind")
        if item.checked <= 0 or not 0 <= item.passed <= item.checked:
            return AdmissionReceipt(False, "invalid-counts")
        if item.created_at > now or item.expires_at <= item.created_at:
            return AdmissionReceipt(False, "invalid-time")
        if not self.keyring.verify(item):
            return AdmissionReceipt(False, "invalid-proof")
        item_digest = digest(evidence_payload(item))
        previous = self.digests.get(item.evidence_id)
        if previous and previous != item_digest:
            return AdmissionReceipt(False, "delivery-conflict")
        self.items[item.evidence_id] = item
        self.digests[item.evidence_id] = item_digest
        return AdmissionReceipt(True, "admitted", item_digest)


@dataclass(frozen=True)
class ExceptionGrant:
    exception_id: str
    agent_id: str
    tenant: str
    record_revision: int
    blocker: str
    owner: str
    approved_by: str
    expires_at: int
    proof: str


@dataclass(frozen=True)
class Approval:
    approval_id: str
    agent_id: str
    tenant: str
    record_revision: int
    target: Lifecycle
    approver: str
    expires_at: int
    decision_digest: str
    proof: str


@dataclass(frozen=True)
class Actor:
    subject: str
    tenant: str
    roles: frozenset[str]
    authorized_until: int


@dataclass(frozen=True)
class Decision:
    state: DecisionState
    agent_id: str
    tenant: str
    record_revision: int
    target: Lifecycle
    blockers: tuple[str, ...]
    waived: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    evidence_set_digest: str
    evaluated_at: int
    decision_digest: str = ""


REQUIRED_EVIDENCE = {
    RiskTier.LOW: frozenset({"threat-model", "security-test"}),
    RiskTier.MEDIUM: frozenset({"threat-model", "security-test", "privacy-review"}),
    RiskTier.HIGH: frozenset({"threat-model", "security-test", "privacy-review", "incident-drill"}),
    RiskTier.CRITICAL: frozenset({"threat-model", "security-test", "privacy-review", "incident-drill", "independent-review"}),
}
NON_WAIVABLE = frozenset({"severe-failure", "missing-kill-switch-owner", "retired-is-terminal"})
TRANSITIONS = {
    Lifecycle.DRAFT: frozenset({Lifecycle.PILOT, Lifecycle.RETIRED}),
    Lifecycle.PILOT: frozenset({Lifecycle.AUTHORIZED, Lifecycle.SUSPENDED, Lifecycle.RETIRED}),
    Lifecycle.AUTHORIZED: frozenset({Lifecycle.SUSPENDED, Lifecycle.RETIRED}),
    Lifecycle.SUSPENDED: frozenset({Lifecycle.PILOT, Lifecycle.RETIRED}),
    Lifecycle.RETIRED: frozenset(),
}


class GovernanceEngine:
    def __init__(self, store: EvidenceStore, exception_keys: dict[str, bytes], approval_keys: dict[str, bytes]):
        self.store = store
        self.exception_keys = dict(exception_keys)
        self.approval_keys = dict(approval_keys)
        self.used_approvals: set[str] = set()

    @staticmethod
    def _proof(value: object, key: bytes, omitted: str) -> str:
        payload = {k: v for k, v in asdict(value).items() if k != omitted}
        return hmac.new(key, digest(payload).encode(), hashlib.sha256).hexdigest()

    def evaluate(self, record: AgentRecord, target: Lifecycle, now: int,
                 exceptions: Iterable[ExceptionGrant] = ()) -> Decision:
        blockers: set[str] = set()
        if target not in TRANSITIONS[record.lifecycle]:
            blockers.add("retired-is-terminal" if record.lifecycle is Lifecycle.RETIRED else "invalid-transition")
        for field_name in ("business_owner", "technical_owner", "security_owner", "purpose", "policy_version", "control_version"):
            if not getattr(record, field_name):
                blockers.add(f"missing:{field_name}")
        if record.risk_tier in {RiskTier.HIGH, RiskTier.CRITICAL} and not record.kill_switch_owner:
            blockers.add("missing-kill-switch-owner")
        if record.review_due_at < now:
            blockers.add("review-overdue")
        applicable = [item for item in self.store.items.values()
                      if item.agent_id == record.agent_id and item.tenant == record.tenant
                      and item.record_revision == record.revision
                      and item.policy_version == record.policy_version
                      and item.control_version == record.control_version]
        latest_by_kind: dict[str, Evidence] = {}
        for item in sorted(applicable, key=lambda value: (value.created_at, value.evidence_id)):
            latest_by_kind[item.kind] = item
        required = REQUIRED_EVIDENCE[record.risk_tier] if target in {Lifecycle.PILOT, Lifecycle.AUTHORIZED} else frozenset()
        for kind in sorted(required - latest_by_kind.keys()):
            blockers.add(f"missing-evidence:{kind}")
        for item in latest_by_kind.values():
            if item.expires_at <= now:
                blockers.add(f"expired-evidence:{item.kind}")
            if item.passed != item.checked:
                blockers.add(f"failed-evidence:{item.kind}")
            if item.severe_failures:
                blockers.add("severe-failure")
        waived: set[str] = set()
        for grant in exceptions:
            key = self.exception_keys.get(grant.approved_by)
            valid = bool(key) and hmac.compare_digest(self._proof(grant, key, "proof"), grant.proof)
            exact = (grant.agent_id, grant.tenant, grant.record_revision) == (record.agent_id, record.tenant, record.revision)
            if valid and exact and grant.owner and grant.expires_at > now and grant.blocker not in NON_WAIVABLE:
                if grant.blocker in blockers:
                    blockers.remove(grant.blocker)
                    waived.add(grant.blocker)
        evidence_ids = tuple(sorted(item.evidence_id for item in latest_by_kind.values()))
        state = DecisionState.READY if not blockers else DecisionState.BLOCKED
        if blockers and all(value.startswith("missing") for value in blockers):
            state = DecisionState.INCOMPLETE
        preliminary = Decision(state, record.agent_id, record.tenant, record.revision, target,
                               tuple(sorted(blockers)), tuple(sorted(waived)), evidence_ids,
                               digest([self.store.digests[item_id] for item_id in evidence_ids]), now)
        return replace(preliminary, decision_digest=digest(asdict(preliminary)))

    def authorize(self, record: AgentRecord, decision: Decision, approval: Approval,
                  operator: Actor, now: int) -> AgentRecord:
        if decision.state is not DecisionState.READY:
            raise PermissionError("decision-not-ready")
        if operator.tenant != record.tenant or operator.authorized_until <= now or "governance-operator" not in operator.roles:
            raise PermissionError("operator-not-authorized")
        if approval.approval_id in self.used_approvals:
            raise PermissionError("approval-replayed")
        exact = (approval.agent_id, approval.tenant, approval.record_revision, approval.target, approval.decision_digest) == (
            record.agent_id, record.tenant, record.revision, decision.target, decision.decision_digest)
        if not exact or approval.expires_at <= now or approval.approver == operator.subject:
            raise PermissionError("approval-scope")
        key = self.approval_keys.get(approval.approver)
        if not key or not hmac.compare_digest(self._proof(approval, key, "proof"), approval.proof):
            raise PermissionError("approval-proof")
        self.used_approvals.add(approval.approval_id)
        return replace(record, lifecycle=approval.target, revision=record.revision + 1)


class Inventory:
    """Optimistic-concurrency inventory; stale writers cannot erase changes."""

    def __init__(self):
        self.records: dict[tuple[str, str], AgentRecord] = {}

    def put(self, record: AgentRecord, expected_revision: int | None) -> None:
        key = (record.tenant, record.agent_id)
        current = self.records.get(key)
        current_revision = current.revision if current else None
        if current_revision != expected_revision:
            raise RuntimeError("revision-conflict")
        self.records[key] = record
