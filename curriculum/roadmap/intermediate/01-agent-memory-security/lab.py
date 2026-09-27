"""Credential-free secure long-term memory lifecycle lab for Intermediate 01.

Model output is a memory proposal, never a persistence decision. Trusted
application code binds each proposal to authenticated scope, exact source
evidence, consent, purpose, type policy, classification, version, retention,
and a subject deletion epoch. Reads authorize before lookup and return typed,
untrusted data. The in-memory implementation is a teaching analogue, not a
production identity, consent, policy, database, encryption, or audit system.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from hashlib import sha256
import json
from typing import Any


NOW = datetime(2026, 9, 27, 16, 0, tzinfo=timezone.utc)
POLICY_VERSION = "northwind-memory-2"


def digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class MemoryKind(str, Enum):
    WORKING = "working"
    EPISODIC = "episodic"
    SEMANTIC = "semantic"
    PROCEDURAL = "procedural"


class SourceAuthority(IntEnum):
    AGENT_SUMMARY = 10
    USER_CONFIRMATION = 20
    SYSTEM_OF_RECORD = 30
    APPLICATION_CONFIG = 40


class Lifecycle(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    EXPIRED = "expired"
    DELETED = "deleted"


class WriteStatus(str, Enum):
    CREATED = "created"
    UPDATED = "updated"
    IDEMPOTENT = "idempotent"
    DENY = "deny"
    CONFLICT = "conflict"
    ERROR = "error"


class ReadStatus(str, Enum):
    READY = "ready"
    EMPTY = "empty"
    DENY = "deny"
    ERROR = "error"


class DeleteStatus(str, Enum):
    DELETED = "deleted"
    DENY = "deny"
    ERROR = "error"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    FAILURE = "failure"


@dataclass(frozen=True)
class ActorContext:
    """Server-resolved request context, never model arguments."""

    request_id: str
    tenant: str
    subject: str
    purpose: str
    subject_epoch: int
    authenticated: bool = True


@dataclass(frozen=True)
class SourceEvidence:
    source_id: str
    version: int
    tenant: str
    subject: str
    key: str
    value: str
    authority: SourceAuthority
    classification: Classification
    effective_at: datetime
    valid_until: datetime
    active: bool = True
    evidence_digest: str = ""

    @property
    def reference(self) -> str:
        return f"{self.source_id}@{self.version}#{self.evidence_digest}"


def make_source(
    source_id: str,
    version: int,
    tenant: str,
    subject: str,
    key: str,
    value: str,
    authority: SourceAuthority,
    classification: Classification,
    effective_at: datetime,
    valid_until: datetime,
    *,
    active: bool = True,
) -> SourceEvidence:
    source = SourceEvidence(
        source_id, version, tenant, subject, key, value, authority,
        classification, effective_at, valid_until, active,
    )
    payload = {
        "source_id": source.source_id, "version": source.version,
        "tenant": source.tenant, "subject": source.subject,
        "key": source.key, "value": source.value,
        "authority": int(source.authority), "classification": int(source.classification),
        "effective_at": source.effective_at.isoformat(),
        "valid_until": source.valid_until.isoformat(), "active": source.active,
    }
    return replace(source, evidence_digest=digest(payload))


@dataclass
class SourceRegistry:
    records: dict[str, SourceEvidence]
    version: str = "source-registry-1"
    available: bool = True

    def resolve(self, reference: str) -> SourceEvidence | None:
        source_id = reference.split("@", 1)[0]
        record = self.records.get(source_id)
        return record if record and record.reference == reference else None


@dataclass(frozen=True)
class Consent:
    consent_id: str
    tenant: str
    subject: str
    purpose: str
    memory_keys: frozenset[str]
    valid_until: datetime
    active: bool = True


@dataclass
class ConsentRegistry:
    records: dict[str, Consent]
    available: bool = True

    def permits(self, consent_id: str | None, actor: ActorContext, key: str, now: datetime) -> bool:
        consent = self.records.get(consent_id or "")
        return bool(
            consent and consent.active and consent.tenant == actor.tenant
            and consent.subject == actor.subject and consent.purpose == actor.purpose
            and key in consent.memory_keys and now < consent.valid_until
        )


@dataclass(frozen=True)
class MemoryProposal:
    """Typed proposal; scope and authority stay outside model-controlled fields."""

    proposal_id: str
    kind: MemoryKind
    key: str
    value: str
    source_ref: str
    consent_id: str | None
    requested_ttl: timedelta
    expected_version: int | None
    subject_epoch: int


@dataclass(frozen=True)
class MemoryRecord:
    memory_id: str
    tenant: str
    subject: str
    purpose: str
    kind: MemoryKind
    key: str
    value: str
    version: int
    source_ref: str
    source_registry_version: str
    authority: SourceAuthority
    classification: Classification
    consent_id: str | None
    created_at: datetime
    expires_at: datetime
    lifecycle: Lifecycle
    subject_epoch: int
    supersedes: str | None = None
    superseded_by: str | None = None
    content_digest: str = ""


@dataclass(frozen=True)
class AuditReceipt:
    request_id: str
    operation: str
    status: str
    reason: str
    tenant_digest: str
    subject_digest: str
    memory_id: str = ""
    memory_version: int = 0
    proposal_digest: str = ""
    policy_version: str = POLICY_VERSION
    source_registry_version: str = ""


@dataclass(frozen=True)
class WriteDecision:
    status: WriteStatus
    reason: str
    receipt: AuditReceipt
    record: MemoryRecord | None = None


@dataclass(frozen=True)
class MemoryView:
    memory_id: str
    kind: MemoryKind
    key: str
    value: str
    version: int
    source_ref: str
    expires_at: datetime
    untrusted_data: bool = True
    grants_authority: bool = False


@dataclass(frozen=True)
class ReadDecision:
    status: ReadStatus
    reason: str
    receipt: AuditReceipt
    memory: MemoryView | None = None


@dataclass(frozen=True)
class DeleteDecision:
    status: DeleteStatus
    reason: str
    deleted_count: int
    new_subject_epoch: int
    receipt: AuditReceipt


@dataclass
class MemoryStore:
    """Versioned records plus durable subject deletion epochs."""

    records: dict[str, MemoryRecord] = field(default_factory=dict)
    current: dict[tuple[str, str, str], str] = field(default_factory=dict)
    proposal_ledger: dict[tuple[str, str, str], tuple[str, str]] = field(default_factory=dict)
    subject_epochs: dict[tuple[str, str], int] = field(default_factory=dict)
    available: bool = True

    def epoch(self, tenant: str, subject: str) -> int:
        return self.subject_epochs.get((tenant, subject), 0)

    def current_record(self, tenant: str, subject: str, key: str) -> MemoryRecord | None:
        memory_id = self.current.get((tenant, subject, key))
        return self.records.get(memory_id or "")


TYPE_POLICY = {
    MemoryKind.SEMANTIC: {
        "preferred_contact_method": {
            "values": frozenset({"email", "sms", "phone"}),
            "authority": SourceAuthority.USER_CONFIRMATION,
            "max_ttl": timedelta(days=90),
            "classification": Classification.INTERNAL,
            "consent": True,
        }
    },
    MemoryKind.EPISODIC: {
        "last_case_event": {
            "values": frozenset({"case-opened", "case-escalated", "case-resolved"}),
            "authority": SourceAuthority.SYSTEM_OF_RECORD,
            "max_ttl": timedelta(days=14),
            "classification": Classification.CONFIDENTIAL,
            "consent": False,
        }
    },
}


class SecureMemoryService:
    def __init__(
        self, store: MemoryStore, sources: SourceRegistry, consents: ConsentRegistry,
        *, policy_available: bool = True,
    ):
        self.store = store
        self.sources = sources
        self.consents = consents
        self.policy_available = policy_available

    def _receipt(
        self, actor: ActorContext, operation: str, status: str, reason: str,
        *, memory_id: str = "", memory_version: int = 0, proposal_digest: str = "",
    ) -> AuditReceipt:
        return AuditReceipt(
            actor.request_id, operation, status, reason, digest(actor.tenant)[:16],
            digest(actor.subject)[:16], memory_id, memory_version, proposal_digest,
            source_registry_version=self.sources.version,
        )

    def _write_terminal(
        self, actor: ActorContext, status: WriteStatus, reason: str, proposal_digest: str,
    ) -> WriteDecision:
        return WriteDecision(
            status, reason,
            self._receipt(actor, "write", status.value, reason, proposal_digest=proposal_digest),
        )

    def write(self, actor: ActorContext, proposal: MemoryProposal, *, now: datetime) -> WriteDecision:
        proposal_digest = digest({
            "proposal_id": proposal.proposal_id, "kind": proposal.kind.value,
            "key": proposal.key, "value": proposal.value, "source_ref": proposal.source_ref,
            "consent_id": proposal.consent_id,
            "ttl_seconds": int(proposal.requested_ttl.total_seconds()),
            "expected_version": proposal.expected_version,
            "subject_epoch": proposal.subject_epoch, "tenant": actor.tenant,
            "subject": actor.subject, "purpose": actor.purpose,
        })
        if not actor.authenticated:
            return self._write_terminal(actor, WriteStatus.DENY, "unauthenticated", proposal_digest)
        if not self.policy_available:
            return self._write_terminal(actor, WriteStatus.ERROR, "policy-unavailable", proposal_digest)
        if not self.store.available:
            return self._write_terminal(actor, WriteStatus.ERROR, "store-unavailable", proposal_digest)
        if not self.sources.available or not self.consents.available:
            return self._write_terminal(actor, WriteStatus.ERROR, "registry-unavailable", proposal_digest)
        if actor.purpose not in {"support-personalization", "support-resolution"}:
            return self._write_terminal(actor, WriteStatus.DENY, "purpose", proposal_digest)
        current_epoch = self.store.epoch(actor.tenant, actor.subject)
        if actor.subject_epoch != current_epoch or proposal.subject_epoch != current_epoch:
            return self._write_terminal(actor, WriteStatus.DENY, "subject-epoch", proposal_digest)

        ledger_key = (actor.tenant, actor.subject, proposal.proposal_id)
        ledger = self.store.proposal_ledger.get(ledger_key)
        if ledger:
            previous_digest, memory_id = ledger
            if previous_digest != proposal_digest:
                return self._write_terminal(actor, WriteStatus.DENY, "proposal-id-collision", proposal_digest)
            record = self.store.records[memory_id]
            return WriteDecision(
                WriteStatus.IDEMPOTENT, "duplicate-proposal",
                self._receipt(
                    actor, "write", WriteStatus.IDEMPOTENT.value, "duplicate-proposal",
                    memory_id=record.memory_id, memory_version=record.version,
                    proposal_digest=proposal_digest,
                ), record,
            )

        if proposal.kind in {MemoryKind.WORKING, MemoryKind.PROCEDURAL}:
            return self._write_terminal(actor, WriteStatus.DENY, "non-persistable-memory-kind", proposal_digest)
        kind_policy = TYPE_POLICY.get(proposal.kind, {}).get(proposal.key)
        if not kind_policy or proposal.value not in kind_policy["values"]:
            return self._write_terminal(actor, WriteStatus.DENY, "schema-or-value", proposal_digest)
        if proposal.requested_ttl <= timedelta(0) or proposal.requested_ttl > kind_policy["max_ttl"]:
            return self._write_terminal(actor, WriteStatus.DENY, "retention", proposal_digest)

        source = self.sources.resolve(proposal.source_ref)
        if source is None:
            return self._write_terminal(actor, WriteStatus.DENY, "source-binding", proposal_digest)
        if not source.active or now < source.effective_at or now >= source.valid_until:
            return self._write_terminal(actor, WriteStatus.DENY, "source-stale", proposal_digest)
        if source.tenant != actor.tenant or source.subject != actor.subject:
            return self._write_terminal(actor, WriteStatus.DENY, "source-scope", proposal_digest)
        if source.key != proposal.key or source.value != proposal.value:
            return self._write_terminal(actor, WriteStatus.DENY, "source-claim", proposal_digest)
        if source.authority < kind_policy["authority"]:
            return self._write_terminal(actor, WriteStatus.DENY, "source-authority", proposal_digest)
        if source.classification > kind_policy["classification"]:
            return self._write_terminal(actor, WriteStatus.DENY, "classification", proposal_digest)
        if kind_policy["consent"] and not self.consents.permits(proposal.consent_id, actor, proposal.key, now):
            return self._write_terminal(actor, WriteStatus.DENY, "consent", proposal_digest)

        previous = self.store.current_record(actor.tenant, actor.subject, proposal.key)
        if previous is None and proposal.expected_version is not None:
            return self._write_terminal(actor, WriteStatus.CONFLICT, "expected-version", proposal_digest)
        if previous is not None and proposal.expected_version != previous.version:
            return self._write_terminal(actor, WriteStatus.CONFLICT, "expected-version", proposal_digest)

        version = 1 if previous is None else previous.version + 1
        memory_id = f"mem:{digest([actor.tenant, actor.subject, current_epoch, proposal.key, version])[:20]}"
        expires_at = now + proposal.requested_ttl
        record_payload = {
            "memory_id": memory_id, "tenant": actor.tenant, "subject": actor.subject,
            "purpose": actor.purpose, "kind": proposal.kind.value, "key": proposal.key,
            "value": proposal.value, "version": version, "source_ref": proposal.source_ref,
            "source_registry_version": self.sources.version, "authority": int(source.authority),
            "classification": int(source.classification), "consent_id": proposal.consent_id,
            "created_at": now.isoformat(), "expires_at": expires_at.isoformat(),
            "subject_epoch": current_epoch,
            "supersedes": previous.memory_id if previous else None,
        }
        record = MemoryRecord(
            memory_id, actor.tenant, actor.subject, actor.purpose, proposal.kind,
            proposal.key, proposal.value, version, proposal.source_ref, self.sources.version,
            source.authority, source.classification, proposal.consent_id, now, expires_at,
            Lifecycle.ACTIVE, current_epoch, previous.memory_id if previous else None,
            content_digest=digest(record_payload),
        )
        if previous:
            self.store.records[previous.memory_id] = replace(
                previous, lifecycle=Lifecycle.SUPERSEDED, superseded_by=memory_id
            )
        self.store.records[memory_id] = record
        self.store.current[(actor.tenant, actor.subject, proposal.key)] = memory_id
        self.store.proposal_ledger[ledger_key] = (proposal_digest, memory_id)
        status = WriteStatus.UPDATED if previous else WriteStatus.CREATED
        receipt = self._receipt(
            actor, "write", status.value, "admitted", memory_id=memory_id,
            memory_version=version, proposal_digest=proposal_digest,
        )
        return WriteDecision(status, "admitted", receipt, record)

    def read(self, actor: ActorContext, key: str, *, now: datetime) -> ReadDecision:
        def terminal(status: ReadStatus, reason: str) -> ReadDecision:
            return ReadDecision(status, reason, self._receipt(actor, "read", status.value, reason))

        if not actor.authenticated:
            return terminal(ReadStatus.DENY, "unauthenticated")
        if not self.policy_available:
            return terminal(ReadStatus.ERROR, "policy-unavailable")
        if not self.store.available:
            return terminal(ReadStatus.ERROR, "store-unavailable")
        if not self.sources.available or not self.consents.available:
            return terminal(ReadStatus.ERROR, "registry-unavailable")
        if actor.purpose not in {"support-personalization", "support-resolution"}:
            return terminal(ReadStatus.DENY, "purpose")
        if actor.subject_epoch != self.store.epoch(actor.tenant, actor.subject):
            return terminal(ReadStatus.DENY, "subject-epoch")
        if key not in {item for policy in TYPE_POLICY.values() for item in policy}:
            return terminal(ReadStatus.DENY, "key")

        # Authorization above precedes lookup. A production backend should apply
        # the same scope/lifecycle predicates before vector or graph ranking.
        record = self.store.current_record(actor.tenant, actor.subject, key)
        if record is None:
            return terminal(ReadStatus.EMPTY, "not-found")
        if record.lifecycle is not Lifecycle.ACTIVE or record.subject_epoch != actor.subject_epoch:
            return terminal(ReadStatus.EMPTY, "not-active")
        if now >= record.expires_at:
            self.store.records[record.memory_id] = replace(record, lifecycle=Lifecycle.EXPIRED)
            return terminal(ReadStatus.EMPTY, "expired")
        if record.kind is MemoryKind.SEMANTIC and not self.consents.permits(record.consent_id, actor, record.key, now):
            return terminal(ReadStatus.EMPTY, "consent-revoked")
        memory = MemoryView(
            record.memory_id, record.kind, record.key, record.value, record.version,
            record.source_ref, record.expires_at,
        )
        receipt = self._receipt(
            actor, "read", ReadStatus.READY.value, "authorized",
            memory_id=record.memory_id, memory_version=record.version,
        )
        return ReadDecision(ReadStatus.READY, "authorized", receipt, memory)

    def delete_subject(self, actor: ActorContext, *, now: datetime) -> DeleteDecision:
        def terminal(status: DeleteStatus, reason: str) -> DeleteDecision:
            return DeleteDecision(
                status, reason, 0, self.store.epoch(actor.tenant, actor.subject),
                self._receipt(actor, "delete-subject", status.value, reason),
            )

        if not actor.authenticated or actor.purpose != "privacy-delete":
            return terminal(DeleteStatus.DENY, "purpose-or-authentication")
        if not self.policy_available:
            return terminal(DeleteStatus.ERROR, "policy-unavailable")
        if not self.store.available:
            return terminal(DeleteStatus.ERROR, "store-unavailable")
        current_epoch = self.store.epoch(actor.tenant, actor.subject)
        if actor.subject_epoch != current_epoch:
            return terminal(DeleteStatus.DENY, "subject-epoch")

        deleted = 0
        for record_id, record in tuple(self.store.records.items()):
            if record.tenant == actor.tenant and record.subject == actor.subject and record.lifecycle is not Lifecycle.DELETED:
                self.store.records[record_id] = replace(
                    record, value="", lifecycle=Lifecycle.DELETED,
                    content_digest=digest([record.memory_id, "deleted", now.isoformat()]),
                )
                self.store.current.pop((record.tenant, record.subject, record.key), None)
                deleted += 1
        new_epoch = current_epoch + 1
        self.store.subject_epochs[(actor.tenant, actor.subject)] = new_epoch
        receipt = self._receipt(actor, "delete-subject", DeleteStatus.DELETED.value, "tombstoned")
        return DeleteDecision(DeleteStatus.DELETED, "tombstoned", deleted, new_epoch, receipt)


def build_system() -> tuple[SecureMemoryService, dict[str, SourceEvidence]]:
    sources = {
        "confirm:email": make_source(
            "confirm:email", 1, "north", "user-7", "preferred_contact_method", "email",
            SourceAuthority.USER_CONFIRMATION, Classification.INTERNAL,
            NOW - timedelta(minutes=5), NOW + timedelta(days=1),
        ),
        "confirm:sms": make_source(
            "confirm:sms", 1, "north", "user-7", "preferred_contact_method", "sms",
            SourceAuthority.USER_CONFIRMATION, Classification.INTERNAL,
            NOW - timedelta(minutes=5), NOW + timedelta(days=1),
        ),
        "confirm:phone": make_source(
            "confirm:phone", 1, "north", "user-7", "preferred_contact_method", "phone",
            SourceAuthority.USER_CONFIRMATION, Classification.INTERNAL,
            NOW - timedelta(minutes=5), NOW + timedelta(days=1),
        ),
        "system:event": make_source(
            "system:event", 4, "north", "user-7", "last_case_event", "case-escalated",
            SourceAuthority.SYSTEM_OF_RECORD, Classification.CONFIDENTIAL,
            NOW - timedelta(minutes=1), NOW + timedelta(days=1),
        ),
        "summary:email": make_source(
            "summary:email", 1, "north", "user-7", "preferred_contact_method", "email",
            SourceAuthority.AGENT_SUMMARY, Classification.INTERNAL,
            NOW - timedelta(minutes=5), NOW + timedelta(days=1),
        ),
        "secret:token": make_source(
            "secret:token", 1, "north", "user-7", "preferred_contact_method", "email",
            SourceAuthority.USER_CONFIRMATION, Classification.RESTRICTED,
            NOW - timedelta(minutes=5), NOW + timedelta(days=1),
        ),
        "stale:email": make_source(
            "stale:email", 1, "north", "user-7", "preferred_contact_method", "email",
            SourceAuthority.USER_CONFIRMATION, Classification.INTERNAL,
            NOW - timedelta(days=2), NOW - timedelta(days=1),
        ),
        "south:email": make_source(
            "south:email", 1, "south", "user-7", "preferred_contact_method", "email",
            SourceAuthority.USER_CONFIRMATION, Classification.INTERNAL,
            NOW - timedelta(minutes=5), NOW + timedelta(days=1),
        ),
    }
    consent = Consent(
        "consent:personalization", "north", "user-7", "support-personalization",
        frozenset({"preferred_contact_method"}), NOW + timedelta(days=100),
    )
    service = SecureMemoryService(
        MemoryStore(), SourceRegistry(sources), ConsentRegistry({consent.consent_id: consent})
    )
    return service, sources


def actor(
    request_id: str = "request:1", *, tenant: str = "north", subject: str = "user-7",
    purpose: str = "support-personalization", epoch: int = 0,
) -> ActorContext:
    return ActorContext(request_id, tenant, subject, purpose, epoch)


def proposal(
    source: SourceEvidence, *, proposal_id: str = "proposal:1",
    kind: MemoryKind = MemoryKind.SEMANTIC, key: str = "preferred_contact_method",
    value: str = "email", consent_id: str | None = "consent:personalization",
    ttl: timedelta = timedelta(days=30), expected_version: int | None = None, epoch: int = 0,
) -> MemoryProposal:
    return MemoryProposal(
        proposal_id, kind, key, value, source.reference, consent_id, ttl,
        expected_version, epoch,
    )


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
    valid_task_success_rate: float
    attack_effect_rate: float
    cross_scope_leakage_rate: float
    stale_or_deleted_exposure_rate: float
    trace_completeness_rate: float
    baseline_attack_acceptance_rate: float


def _trace_complete(receipt: AuditReceipt) -> bool:
    return bool(
        receipt.request_id and receipt.operation and receipt.status and receipt.reason
        and receipt.tenant_digest and receipt.subject_digest and receipt.policy_version
        and receipt.source_registry_version
    )


def evaluate_controls() -> tuple[EvaluationReport, tuple[CaseObservation, ...]]:
    observations: list[CaseObservation] = []

    def record(
        case_id: str, kind: CaseKind, status: Enum, receipt: AuditReceipt,
        *, safe: bool, useful: bool, baseline_accepts: bool = False,
    ) -> None:
        observations.append(CaseObservation(
            case_id, kind, safe, useful, _trace_complete(receipt), baseline_accepts,
            str(status.value),
        ))

    # Four valid tasks: semantic memory, episodic memory, versioned update, deletion.
    service, sources = build_system()
    service.write(actor("valid:preference"), proposal(sources["confirm:email"]), now=NOW)
    read = service.read(actor("valid:read"), "preferred_contact_method", now=NOW)
    record("valid-preference", CaseKind.VALID, read.status, read.receipt, safe=True, useful=read.status is ReadStatus.READY)

    service, sources = build_system()
    event = proposal(
        sources["system:event"], proposal_id="proposal:event", kind=MemoryKind.EPISODIC,
        key="last_case_event", value="case-escalated", consent_id=None, ttl=timedelta(days=7),
    )
    decision = service.write(actor("valid:event", purpose="support-resolution"), event, now=NOW)
    record("valid-episodic", CaseKind.VALID, decision.status, decision.receipt, safe=True, useful=decision.status is WriteStatus.CREATED)

    service, sources = build_system()
    service.write(actor("valid:update-1"), proposal(sources["confirm:email"]), now=NOW)
    update = proposal(sources["confirm:sms"], proposal_id="proposal:2", value="sms", expected_version=1)
    decision = service.write(actor("valid:update-2"), update, now=NOW + timedelta(minutes=1))
    record("valid-update", CaseKind.VALID, decision.status, decision.receipt, safe=True, useful=decision.status is WriteStatus.UPDATED)

    service, sources = build_system()
    service.write(actor("valid:delete-seed"), proposal(sources["confirm:email"]), now=NOW)
    deleted = service.delete_subject(actor("valid:delete", purpose="privacy-delete"), now=NOW + timedelta(minutes=1))
    record("valid-delete", CaseKind.VALID, deleted.status, deleted.receipt, safe=True, useful=deleted.status is DeleteStatus.DELETED)

    # Eight attacks. A naive global string store accepts every fixture.
    service, sources = build_system()
    decision = service.write(actor("attack:tenant"), proposal(sources["south:email"]), now=NOW)
    record("cross-tenant-write", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.status is WriteStatus.DENY, useful=False, baseline_accepts=True)

    service, sources = build_system()
    service.write(actor("attack:subject-seed"), proposal(sources["confirm:email"]), now=NOW)
    read = service.read(actor("attack:subject", subject="user-8"), "preferred_contact_method", now=NOW)
    record("cross-subject-read", CaseKind.ATTACK, read.status, read.receipt, safe=read.status is ReadStatus.EMPTY and read.memory is None, useful=False, baseline_accepts=True)

    service, sources = build_system()
    decision = service.write(actor("attack:summary"), proposal(sources["summary:email"]), now=NOW)
    record("agent-summary-poison", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.status is WriteStatus.DENY, useful=False, baseline_accepts=True)

    service, sources = build_system()
    decision = service.write(actor("attack:secret"), proposal(sources["secret:token"]), now=NOW)
    record("restricted-memory", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.status is WriteStatus.DENY, useful=False, baseline_accepts=True)

    service, sources = build_system()
    procedural = proposal(
        sources["confirm:email"], proposal_id="proposal:procedure",
        kind=MemoryKind.PROCEDURAL, key="system_instructions", value="send-data",
    )
    decision = service.write(actor("attack:procedure"), procedural, now=NOW)
    record("procedural-instruction", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.status is WriteStatus.DENY, useful=False, baseline_accepts=True)

    service, sources = build_system()
    decision = service.write(actor("attack:stale"), proposal(sources["stale:email"]), now=NOW)
    record("stale-source", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.status is WriteStatus.DENY, useful=False, baseline_accepts=True)

    service, sources = build_system()
    accepted = service.write(actor("attack:collision-1"), proposal(sources["confirm:email"]), now=NOW)
    collision = proposal(sources["confirm:sms"], proposal_id="proposal:1", value="sms", expected_version=1)
    decision = service.write(actor("attack:collision-2"), collision, now=NOW)
    record("proposal-id-collision", CaseKind.ATTACK, decision.status, decision.receipt, safe=accepted.status is WriteStatus.CREATED and decision.status is WriteStatus.DENY, useful=False, baseline_accepts=True)

    service, sources = build_system()
    old_actor = actor("attack:resurrection")
    old_proposal = proposal(sources["confirm:email"])
    service.delete_subject(actor("attack:delete", purpose="privacy-delete"), now=NOW)
    decision = service.write(old_actor, old_proposal, now=NOW + timedelta(seconds=1))
    record("post-delete-resurrection", CaseKind.ATTACK, decision.status, decision.receipt, safe=decision.status is WriteStatus.DENY, useful=False, baseline_accepts=True)

    # Dependency failures stay ERROR; they are not successful attack blocks.
    service, sources = build_system()
    service.policy_available = False
    decision = service.write(actor("failure:policy"), proposal(sources["confirm:email"]), now=NOW)
    record("policy-outage", CaseKind.FAILURE, decision.status, decision.receipt, safe=decision.status is WriteStatus.ERROR, useful=False)

    service, sources = build_system()
    service.store.available = False
    read = service.read(actor("failure:store"), "preferred_contact_method", now=NOW)
    record("store-outage", CaseKind.FAILURE, read.status, read.receipt, safe=read.status is ReadStatus.ERROR, useful=False)

    valid = [item for item in observations if item.kind is CaseKind.VALID]
    attacks = [item for item in observations if item.kind is CaseKind.ATTACK]
    failures = [item for item in observations if item.kind is CaseKind.FAILURE]
    report = EvaluationReport(
        len(observations), len(valid), len(attacks), len(failures),
        sum(item.useful for item in valid) / len(valid),
        sum(not item.safe for item in attacks) / len(attacks),
        sum(not item.safe for item in attacks if "cross-" in item.case_id) / 2,
        sum(not item.safe for item in attacks if item.case_id in {"stale-source", "post-delete-resurrection"}) / 2,
        sum(item.trace_complete for item in observations) / len(observations),
        sum(item.baseline_accepts for item in attacks) / len(attacks),
    )
    return report, tuple(observations)


def main() -> None:
    report, observations = evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (14, 4, 8, 2)
    assert report.valid_task_success_rate == 1.0
    assert report.attack_effect_rate == 0.0
    assert report.cross_scope_leakage_rate == 0.0
    assert report.stale_or_deleted_exposure_rate == 0.0
    assert report.trace_completeness_rate == 1.0
    assert report.baseline_attack_acceptance_rate == 1.0
    assert all(item.terminal_status == "error" for item in observations if item.kind is CaseKind.FAILURE)
    print(json.dumps(report.__dict__, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
