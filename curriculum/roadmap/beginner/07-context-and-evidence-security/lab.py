"""Credential-free context and evidence security lab for Foundation 07.

The model never receives arbitrary source records. A trusted context compiler
binds candidate references to a registry, applies authorization and lifecycle
policy, resolves authority, surfaces conflicts, enforces a budget, and emits an
exact evidence manifest. A separate release verifier treats generated claims
and citations as proposals. In-memory state is a teaching analogue, not a
production identity, policy, catalog, signing, or audit system.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum
from hashlib import sha256
import json
from typing import Any, Iterable


POLICY_VERSION = "northwind-context-1"


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(encoded.encode()).hexdigest()


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class Authority(IntEnum):
    USER_ASSERTION = 10
    OBSERVATION = 20
    CURATED_GUIDANCE = 30
    SYSTEM_OF_RECORD = 40
    POLICY = 50


class SourceKind(str, Enum):
    POLICY = "policy"
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_RESULT = "tool-result"
    MEMORY = "memory"
    HANDOFF = "handoff"


class Lifecycle(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class CompilationStatus(str, Enum):
    READY = "ready"
    INSUFFICIENT = "insufficient"
    CONFLICT = "conflict"
    DENY = "deny"
    ERROR = "error"


class ReleaseStatus(str, Enum):
    ANSWERED = "answered"
    ABSTAINED = "abstained"
    BLOCKED = "blocked"
    ERROR = "error"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    FAILURE = "failure"


@dataclass(frozen=True)
class Claim:
    key: str
    value: str


@dataclass(frozen=True)
class EvidenceRecord:
    source_id: str
    version: int
    tenant: str
    kind: SourceKind
    classification: Classification
    authority: Authority
    locator: str
    claims: tuple[Claim, ...]
    text: str
    effective_at: datetime
    valid_until: datetime
    allowed_purposes: frozenset[str]
    subject_scope: frozenset[str] = frozenset()
    lifecycle: Lifecycle = Lifecycle.ACTIVE
    superseded_by: str | None = None
    authorized: bool = True
    root_lineage: str = ""
    cost_units: int = 1
    digest: str = ""

    @property
    def reference(self) -> str:
        return f"{self.source_id}@{self.version}#{self.digest}"


def make_evidence(
    source_id: str,
    version: int,
    tenant: str,
    kind: SourceKind,
    classification: Classification,
    authority: Authority,
    locator: str,
    claims: Iterable[tuple[str, str]],
    text: str,
    effective_at: datetime,
    valid_until: datetime,
    allowed_purposes: Iterable[str] = ("support-resolution",),
    **overrides: Any,
) -> EvidenceRecord:
    record = EvidenceRecord(
        source_id=source_id,
        version=version,
        tenant=tenant,
        kind=kind,
        classification=classification,
        authority=authority,
        locator=locator,
        claims=tuple(Claim(*claim) for claim in claims),
        text=text,
        effective_at=effective_at,
        valid_until=valid_until,
        allowed_purposes=frozenset(allowed_purposes),
        root_lineage=overrides.pop("root_lineage", source_id),
        **overrides,
    )
    payload = {
        "source_id": record.source_id,
        "version": record.version,
        "tenant": record.tenant,
        "kind": record.kind.value,
        "classification": int(record.classification),
        "authority": int(record.authority),
        "locator": record.locator,
        "claims": [(claim.key, claim.value) for claim in record.claims],
        "text": record.text,
        "effective_at": record.effective_at.isoformat(),
        "valid_until": record.valid_until.isoformat(),
        "purposes": sorted(record.allowed_purposes),
        "subjects": sorted(record.subject_scope),
        "lifecycle": record.lifecycle.value,
        "superseded_by": record.superseded_by,
        "authorized": record.authorized,
        "root_lineage": record.root_lineage,
        "cost_units": record.cost_units,
    }
    return replace(record, digest=_digest(payload))


@dataclass(frozen=True)
class CandidateRef:
    source_id: str
    version: int
    digest: str

    @classmethod
    def exact(cls, record: EvidenceRecord) -> "CandidateRef":
        return cls(record.source_id, record.version, record.digest)


@dataclass
class EvidenceRegistry:
    records: dict[str, EvidenceRecord]
    version: str = "registry-1"
    available: bool = True

    def get(self, source_id: str) -> EvidenceRecord | None:
        return self.records.get(source_id)


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    subject: str
    tenant: str
    clearance: Classification
    purpose: str
    required_claims: tuple[str, ...]
    authenticated: bool = True


@dataclass(frozen=True)
class CandidateDecision:
    source_id: str
    admitted: bool
    reason: str
    reference: str = ""


@dataclass(frozen=True)
class ManifestEntry:
    reference: str
    source_id: str
    version: int
    digest: str
    kind: SourceKind
    authority: Authority
    classification: Classification
    locator: str
    root_lineage: str
    claims: tuple[Claim, ...]
    text: str


@dataclass(frozen=True)
class ResolvedClaim:
    key: str
    value: str
    authority: Authority
    supporting_refs: tuple[str, ...]


@dataclass(frozen=True)
class ContextManifest:
    status: CompilationStatus
    reason: str
    entries: tuple[ManifestEntry, ...]
    resolved_claims: tuple[ResolvedClaim, ...]
    decisions: tuple[CandidateDecision, ...]
    missing_claims: tuple[str, ...]
    conflict_claims: tuple[str, ...]
    manifest_digest: str
    trace_id: str
    request_digest: str
    policy_version: str
    registry_version: str
    rendered_context: str


class ContextCompiler:
    def __init__(self, registry: EvidenceRegistry, *, policy_available: bool = True):
        self.registry = registry
        self.policy_available = policy_available

    def _admit(self, request: RequestContext, candidate: CandidateRef, now: datetime) -> tuple[EvidenceRecord | None, str]:
        record = self.registry.get(candidate.source_id)
        if record is None:
            return None, "unknown-source"
        if record.version != candidate.version or record.digest != candidate.digest:
            return None, "source-binding"
        if not record.authorized:
            return None, "source-unauthorized"
        if record.tenant not in {request.tenant, "shared"}:
            return None, "tenant"
        if record.subject_scope and request.subject not in record.subject_scope:
            return None, "subject-scope"
        if record.classification > request.clearance:
            return None, "classification"
        if request.purpose not in record.allowed_purposes:
            return None, "purpose"
        if record.lifecycle is Lifecycle.REVOKED:
            return None, "revoked"
        if record.lifecycle is Lifecycle.SUPERSEDED or record.superseded_by:
            return None, "superseded"
        if now < record.effective_at or now >= record.valid_until:
            return None, "stale"
        return record, "admitted"

    def compile(
        self,
        request: RequestContext,
        candidates: Iterable[CandidateRef],
        *,
        now: datetime,
        max_context_units: int = 4,
    ) -> ContextManifest:
        candidate_list = tuple(candidates)
        request_digest = _digest({
            "request_id": request.request_id,
            "subject": request.subject,
            "tenant": request.tenant,
            "clearance": int(request.clearance),
            "purpose": request.purpose,
            "required_claims": request.required_claims,
        })
        trace_id = f"trace:{request.request_id}"

        def terminal(status: CompilationStatus, reason: str) -> ContextManifest:
            return ContextManifest(status, reason, (), (), (), request.required_claims, (), "", trace_id, request_digest, POLICY_VERSION, self.registry.version, "")

        if not request.authenticated:
            return terminal(CompilationStatus.DENY, "unauthenticated")
        if not self.policy_available:
            return terminal(CompilationStatus.ERROR, "policy-unavailable")
        if not self.registry.available:
            return terminal(CompilationStatus.ERROR, "registry-unavailable")
        if max_context_units < 1:
            return terminal(CompilationStatus.ERROR, "invalid-context-budget")

        decisions: list[CandidateDecision] = []
        eligible: list[EvidenceRecord] = []
        seen_candidates: set[tuple[str, int, str]] = set()
        for candidate in candidate_list:
            candidate_key = (candidate.source_id, candidate.version, candidate.digest)
            if candidate_key in seen_candidates:
                decisions.append(CandidateDecision(candidate.source_id, False, "duplicate-candidate"))
                continue
            seen_candidates.add(candidate_key)
            record, reason = self._admit(request, candidate, now)
            decisions.append(CandidateDecision(candidate.source_id, record is not None, reason, record.reference if record else ""))
            if record:
                eligible.append(record)

        resolved: list[ResolvedClaim] = []
        missing: list[str] = []
        conflicts: list[str] = []
        for key in request.required_claims:
            supporting = [(record, claim) for record in eligible for claim in record.claims if claim.key == key]
            if not supporting:
                missing.append(key)
                continue
            highest = max(record.authority for record, _ in supporting)
            authoritative = [(record, claim) for record, claim in supporting if record.authority is highest]
            values = {claim.value for _, claim in authoritative}
            if len(values) != 1:
                conflicts.append(key)
                continue
            value = next(iter(values))
            refs = tuple(sorted(record.reference for record, claim in authoritative if claim.value == value))
            resolved.append(ResolvedClaim(key, value, highest, refs))

        required_refs = {ref for item in resolved for ref in item.supporting_refs}
        ordered = sorted(
            eligible,
            key=lambda record: (
                record.reference not in required_refs,
                -int(record.authority),
                -record.effective_at.timestamp(),
                record.source_id,
            ),
        )
        selected: list[EvidenceRecord] = []
        used = 0
        for record in ordered:
            if used + record.cost_units <= max_context_units:
                selected.append(record)
                used += record.cost_units
            else:
                decisions = [replace(item, admitted=False, reason="budget-excluded") if item.source_id == record.source_id else item for item in decisions]

        selected_refs = {record.reference for record in selected}
        for claim in resolved:
            if not selected_refs.intersection(claim.supporting_refs):
                missing.append(claim.key)

        if conflicts:
            status, reason = CompilationStatus.CONFLICT, "authoritative-conflict"
        elif missing:
            status, reason = CompilationStatus.INSUFFICIENT, "required-evidence-missing"
        else:
            status, reason = CompilationStatus.READY, "context-ready"

        entries = tuple(
            ManifestEntry(
                record.reference, record.source_id, record.version, record.digest, record.kind,
                record.authority, record.classification, record.locator, record.root_lineage,
                record.claims, record.text,
            )
            for record in selected
        )
        rendered = "\n\n".join(
            f'<evidence ref="{entry.reference}" kind="{entry.kind.value}" authority="{entry.authority.name}">\n{entry.text}\n</evidence>'
            for entry in entries
        )
        manifest_digest = _digest({
            "request": request_digest,
            "policy": POLICY_VERSION,
            "registry": self.registry.version,
            "entries": [entry.reference for entry in entries],
            "resolved": [(item.key, item.value, item.supporting_refs) for item in resolved],
            "status": status.value,
        })
        return ContextManifest(
            status, reason, entries, tuple(resolved), tuple(decisions), tuple(sorted(set(missing))),
            tuple(sorted(conflicts)), manifest_digest, trace_id, request_digest, POLICY_VERSION,
            self.registry.version, rendered,
        )


@dataclass(frozen=True)
class DraftClaim:
    key: str
    value: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class ReleaseDecision:
    status: ReleaseStatus
    reason: str
    released_claims: tuple[DraftClaim, ...]
    trace_id: str
    manifest_digest: str


class ReleaseVerifier:
    def __init__(self, registry: EvidenceRegistry):
        self.registry = registry

    def verify(self, manifest: ContextManifest, claims: Iterable[DraftClaim], *, now: datetime) -> ReleaseDecision:
        if not self.registry.available:
            return ReleaseDecision(ReleaseStatus.ERROR, "registry-unavailable", (), manifest.trace_id, manifest.manifest_digest)
        if self.registry.version != manifest.registry_version:
            return ReleaseDecision(ReleaseStatus.BLOCKED, "registry-version-changed", (), manifest.trace_id, manifest.manifest_digest)
        if manifest.status in {CompilationStatus.CONFLICT, CompilationStatus.INSUFFICIENT}:
            return ReleaseDecision(ReleaseStatus.ABSTAINED, manifest.reason, (), manifest.trace_id, manifest.manifest_digest)
        if manifest.status in {CompilationStatus.ERROR, CompilationStatus.DENY}:
            return ReleaseDecision(ReleaseStatus.ERROR, manifest.reason, (), manifest.trace_id, manifest.manifest_digest)

        entries = {entry.reference: entry for entry in manifest.entries}
        resolved = {claim.key: claim for claim in manifest.resolved_claims}
        checked = tuple(claims)
        if not checked:
            return ReleaseDecision(ReleaseStatus.ABSTAINED, "no-supported-claims", (), manifest.trace_id, manifest.manifest_digest)
        for claim in checked:
            expected = resolved.get(claim.key)
            if expected is None or expected.value != claim.value:
                return ReleaseDecision(ReleaseStatus.BLOCKED, "claim-not-resolved", (), manifest.trace_id, manifest.manifest_digest)
            if not claim.evidence_refs:
                return ReleaseDecision(ReleaseStatus.BLOCKED, "citation-required", (), manifest.trace_id, manifest.manifest_digest)
            roots: set[str] = set()
            supported = False
            for reference in claim.evidence_refs:
                entry = entries.get(reference)
                if entry is None:
                    return ReleaseDecision(ReleaseStatus.BLOCKED, "citation-not-in-manifest", (), manifest.trace_id, manifest.manifest_digest)
                current = self.registry.get(entry.source_id)
                if current is None or current.reference != reference:
                    return ReleaseDecision(ReleaseStatus.BLOCKED, "citation-stale", (), manifest.trace_id, manifest.manifest_digest)
                if current.lifecycle is not Lifecycle.ACTIVE or current.superseded_by or now >= current.valid_until:
                    return ReleaseDecision(ReleaseStatus.BLOCKED, "citation-stale", (), manifest.trace_id, manifest.manifest_digest)
                roots.add(entry.root_lineage)
                if any(item.key == claim.key and item.value == claim.value for item in entry.claims):
                    supported = True
            if not supported:
                return ReleaseDecision(ReleaseStatus.BLOCKED, "citation-does-not-support-claim", (), manifest.trace_id, manifest.manifest_digest)
            if len(roots) < len(claim.evidence_refs):
                return ReleaseDecision(ReleaseStatus.BLOCKED, "duplicate-lineage", (), manifest.trace_id, manifest.manifest_digest)
        return ReleaseDecision(ReleaseStatus.ANSWERED, "verified-release", checked, manifest.trace_id, manifest.manifest_digest)


def unsafe_concat_baseline(candidates: Iterable[CandidateRef], draft: Iterable[DraftClaim]) -> bool:
    """Deliberately unsafe: presence and citation-looking strings imply acceptance."""
    return bool(tuple(candidates)) and all(claim.evidence_refs for claim in draft)


NOW = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)


def build_registry(now: datetime = NOW) -> EvidenceRegistry:
    records = [
        make_evidence("policy:retention", 3, "north", SourceKind.POLICY, Classification.CONFIDENTIAL, Authority.POLICY, "policy://retention#current", [("retention_days", "30")], "Approved case-artifact retention is 30 days.", now - timedelta(days=30), now + timedelta(days=365)),
        make_evidence("case:42", 7, "north", SourceKind.TOOL_RESULT, Classification.CONFIDENTIAL, Authority.SYSTEM_OF_RECORD, "case://42#status", [("case_status", "resolved")], "Case 42 is resolved.", now - timedelta(hours=1), now + timedelta(days=1)),
        make_evidence("runbook:closure", 2, "shared", SourceKind.RETRIEVED, Classification.INTERNAL, Authority.CURATED_GUIDANCE, "runbook://closure", [("closure_step", "notify-owner")], "Notify the case owner after closure.", now - timedelta(days=10), now + timedelta(days=90), allowed_purposes=("support-resolution", "training")),
        make_evidence("observation:retention", 1, "north", SourceKind.MEMORY, Classification.INTERNAL, Authority.OBSERVATION, "memory://retention", [("retention_days", "90")], "A prior summary says 90 days.", now - timedelta(days=1), now + timedelta(days=5)),
        make_evidence("policy:retention-old", 2, "north", SourceKind.POLICY, Classification.CONFIDENTIAL, Authority.POLICY, "policy://retention#v2", [("retention_days", "90")], "The former retention period was 90 days.", now - timedelta(days=400), now + timedelta(days=100), lifecycle=Lifecycle.SUPERSEDED, superseded_by="policy:retention@3"),
        make_evidence("case:south:9", 4, "south", SourceKind.TOOL_RESULT, Classification.CONFIDENTIAL, Authority.SYSTEM_OF_RECORD, "case://south/9", [("case_status", "resolved")], "South case is resolved.", now - timedelta(hours=1), now + timedelta(days=1)),
        make_evidence("secret:fraud", 1, "north", SourceKind.RETRIEVED, Classification.RESTRICTED, Authority.SYSTEM_OF_RECORD, "vault://fraud", [("risk_state", "high")], "Restricted fraud assessment.", now - timedelta(hours=1), now + timedelta(days=1)),
        make_evidence("case:conflict-a", 1, "north", SourceKind.TOOL_RESULT, Classification.CONFIDENTIAL, Authority.SYSTEM_OF_RECORD, "case://42/a", [("case_owner", "alice")], "Owner is Alice.", now - timedelta(hours=1), now + timedelta(days=1)),
        make_evidence("case:conflict-b", 1, "north", SourceKind.TOOL_RESULT, Classification.CONFIDENTIAL, Authority.SYSTEM_OF_RECORD, "case://42/b", [("case_owner", "bob")], "Owner is Bob.", now - timedelta(hours=1), now + timedelta(days=1)),
        make_evidence("case:unretrieved", 1, "north", SourceKind.TOOL_RESULT, Classification.CONFIDENTIAL, Authority.SYSTEM_OF_RECORD, "case://99", [("case_status", "open")], "Case 99 is open.", now - timedelta(hours=1), now + timedelta(days=1)),
    ]
    return EvidenceRegistry({record.source_id: record for record in records})


def request_for(key: str, request_id: str = "request:demo") -> RequestContext:
    return RequestContext(request_id, "analyst:alice", "north", Classification.CONFIDENTIAL, "support-resolution", (key,))


def compile_and_release(
    registry: EvidenceRegistry,
    request: RequestContext,
    source_ids: Iterable[str],
    draft_factory: Any | None = None,
    *,
    now: datetime = NOW,
    policy_available: bool = True,
) -> tuple[ContextManifest, ReleaseDecision, tuple[DraftClaim, ...]]:
    refs = tuple(CandidateRef.exact(registry.records[source_id]) for source_id in source_ids)
    manifest = ContextCompiler(registry, policy_available=policy_available).compile(request, refs, now=now)
    if draft_factory is None and manifest.resolved_claims:
        item = manifest.resolved_claims[0]
        draft = (DraftClaim(item.key, item.value, (item.supporting_refs[0],)),)
    elif draft_factory is None:
        draft = ()
    else:
        draft = tuple(draft_factory(manifest))
    return manifest, ReleaseVerifier(registry).verify(manifest, draft, now=now), draft


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    kind: CaseKind
    manifest: ContextManifest
    release: ReleaseDecision
    baseline_accepts: bool
    trace_complete: bool


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    valid_task_success_rate: float
    attack_effect_rate: float
    attack_block_rate: float
    baseline_attack_acceptance_rate: float
    unauthorized_admission_rate: float
    stale_admission_rate: float
    conflict_surfacing_rate: float
    citation_integrity_rate: float
    trace_completeness_rate: float


def evaluate_controls(now: datetime = NOW) -> tuple[EvaluationReport, tuple[EvaluationCase, ...]]:
    cases: list[EvaluationCase] = []

    def add(name: str, kind: CaseKind, registry: EvidenceRegistry, request: RequestContext, ids: tuple[str, ...], draft_factory: Any | None = None, *, refs: tuple[CandidateRef, ...] | None = None, policy_available: bool = True) -> None:
        candidate_refs = refs or tuple(CandidateRef.exact(registry.records[item]) for item in ids)
        manifest = ContextCompiler(registry, policy_available=policy_available).compile(request, candidate_refs, now=now)
        if draft_factory is None and manifest.resolved_claims:
            resolved = manifest.resolved_claims[0]
            draft = (DraftClaim(resolved.key, resolved.value, (resolved.supporting_refs[0],)),)
        elif draft_factory is None:
            draft = ()
        else:
            draft = tuple(draft_factory(manifest, registry))
        release = ReleaseVerifier(registry).verify(manifest, draft, now=now)
        trace_complete = bool(manifest.trace_id and manifest.request_digest and manifest.policy_version and manifest.registry_version and (manifest.manifest_digest or manifest.status in {CompilationStatus.ERROR, CompilationStatus.DENY}))
        cases.append(EvaluationCase(name, kind, manifest, release, unsafe_concat_baseline(candidate_refs, draft), trace_complete))

    # Four legitimate tasks.
    add("current-policy", CaseKind.VALID, build_registry(now), request_for("retention_days", "request:v1"), ("policy:retention",))
    add("current-system-record", CaseKind.VALID, build_registry(now), request_for("case_status", "request:v2"), ("case:42",))
    add("shared-curated-guidance", CaseKind.VALID, build_registry(now), request_for("closure_step", "request:v3"), ("runbook:closure",))
    add("authority-over-observation", CaseKind.VALID, build_registry(now), request_for("retention_days", "request:v4"), ("observation:retention", "policy:retention"))

    # Eight adversarial or unsafe evidence paths.
    add("cross-tenant", CaseKind.ATTACK, build_registry(now), request_for("case_status", "request:a1"), ("case:south:9",))
    add("classification-overreach", CaseKind.ATTACK, build_registry(now), request_for("risk_state", "request:a2"), ("secret:fraud",))
    tampered_registry = build_registry(now)
    good = tampered_registry.records["policy:retention"]
    add("digest-tamper", CaseKind.ATTACK, tampered_registry, request_for("retention_days", "request:a3"), (), refs=(CandidateRef(good.source_id, good.version, "0" * 64),))
    add("superseded-evidence", CaseKind.ATTACK, build_registry(now), request_for("retention_days", "request:a4"), ("policy:retention-old",))
    add("authoritative-conflict", CaseKind.ATTACK, build_registry(now), request_for("case_owner", "request:a5"), ("case:conflict-a", "case:conflict-b"))
    add("fabricated-citation", CaseKind.ATTACK, build_registry(now), request_for("retention_days", "request:a6"), ("policy:retention",), lambda m, r: (DraftClaim("retention_days", "30", ("fabricated@1#bad",)),))
    add("citation-laundering", CaseKind.ATTACK, build_registry(now), request_for("retention_days", "request:a7"), ("policy:retention", "case:42"), lambda m, r: (DraftClaim("retention_days", "30", (r.records["case:42"].reference,)),))
    add("unretrieved-citation", CaseKind.ATTACK, build_registry(now), request_for("case_status", "request:a8"), ("case:42",), lambda m, r: (DraftClaim("case_status", "resolved", (r.records["case:unretrieved"].reference,)),))

    # Dependency failures remain errors, not attack blocks.
    add("policy-outage", CaseKind.FAILURE, build_registry(now), request_for("retention_days", "request:f1"), ("policy:retention",), policy_available=False)
    unavailable = build_registry(now)
    unavailable.available = False
    add("registry-outage", CaseKind.FAILURE, unavailable, request_for("retention_days", "request:f2"), ("policy:retention",))

    valid = [case for case in cases if case.kind is CaseKind.VALID]
    attacks = [case for case in cases if case.kind is CaseKind.ATTACK]
    failures = [case for case in cases if case.kind is CaseKind.FAILURE]
    protected_reasons = {"tenant", "subject-scope", "classification", "purpose", "source-unauthorized", "source-binding", "revoked", "superseded", "stale"}
    protected = [decision for case in cases for decision in case.manifest.decisions if decision.reason in protected_reasons]
    unauthorized = [decision for decision in protected if decision.admitted and decision.reason in {"tenant", "subject-scope", "classification", "purpose", "source-unauthorized", "source-binding"}]
    stale = [decision for decision in protected if decision.admitted and decision.reason in {"revoked", "superseded", "stale"}]
    conflict_cases = [case for case in attacks if case.name == "authoritative-conflict"]
    answered = [case for case in valid if case.release.status is ReleaseStatus.ANSWERED]
    report = EvaluationReport(
        len(cases), len(valid), len(attacks), len(failures),
        sum(case.release.status is ReleaseStatus.ANSWERED for case in valid) / len(valid),
        sum(case.release.status is ReleaseStatus.ANSWERED for case in attacks) / len(attacks),
        sum(case.release.status in {ReleaseStatus.ABSTAINED, ReleaseStatus.BLOCKED} for case in attacks) / len(attacks),
        sum(case.baseline_accepts for case in attacks) / len(attacks),
        len(unauthorized) / len(protected) if protected else 0.0,
        len(stale) / len(protected) if protected else 0.0,
        sum(case.manifest.status is CompilationStatus.CONFLICT for case in conflict_cases) / len(conflict_cases),
        sum(case.release.reason == "verified-release" for case in answered) / len(answered),
        sum(case.trace_complete for case in cases) / len(cases),
    )
    return report, tuple(cases)


def demo() -> EvaluationReport:
    report, cases = evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (14, 4, 8, 2)
    assert report.valid_task_success_rate == report.attack_block_rate == 1.0
    assert report.attack_effect_rate == report.unauthorized_admission_rate == report.stale_admission_rate == 0.0
    assert report.conflict_surfacing_rate == report.citation_integrity_rate == report.trace_completeness_rate == 1.0
    assert all(case.release.status is ReleaseStatus.ERROR for case in cases if case.kind is CaseKind.FAILURE)
    return report


if __name__ == "__main__":
    print(json.dumps(demo().__dict__, indent=2, sort_keys=True))
