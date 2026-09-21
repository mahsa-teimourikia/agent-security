"""Observable trust-boundary inventory for a research-and-support agent.

The model proposes work. Authenticated application context, a versioned boundary
catalog, and deterministic policy decide whether data or authority may cross a
boundary. The lab is intentionally credential-free and performs no real effects.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
import hmac
import json
from threading import Lock


POLICY_VERSION = "boundary-policy-1"
DEMO_GRANT_KEY = b"local-teaching-key-not-for-production"


class Zone(str, Enum):
    EXTERNAL = "external"
    APPLICATION = "application"
    AGENT = "agent-runtime"
    DATA = "data-services"
    ENTERPRISE = "enterprise-systems"
    OPERATIONS = "operations"


class Operation(str, Enum):
    SUBMIT_REQUEST = "submit_request"
    BUILD_CONTEXT = "build_context"
    GENERATE_PROPOSAL = "generate_proposal"
    READ_EVIDENCE = "read_evidence"
    READ_MEMORY = "read_memory"
    PROPOSE_TICKET = "propose_ticket"
    CREATE_TICKET = "create_ticket"
    EMIT_DECISION = "emit_decision"
    REVOKE_EFFECTS = "revoke_effects"


class CaseKind(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    DEPENDENCY_FAILURE = "dependency_failure"


@dataclass(frozen=True)
class BoundarySpec:
    boundary_id: str
    source: Zone
    target: Zone
    asset: str
    allowed_operations: frozenset[Operation]
    required_scope: str
    enforcement_owner: str
    evidence: tuple[str, ...]
    consequence: str = "data"
    fail_mode: str = "closed"


@dataclass(frozen=True)
class ActorContext:
    """Server-owned identity; never constructed from prompt or model output."""

    subject: str
    tenant: str
    scopes: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class BoundaryRequest:
    """Untrusted proposal to cross one declared boundary."""

    request_id: str
    boundary_id: str
    source: Zone
    target: Zone
    operation: Operation
    resource_id: str
    resource_tenant: str
    content_digest: str
    evidence_ids: tuple[str, ...] = ()
    provenance_verified: bool = False
    claimed_subject: str | None = None
    effect_grant_id: str | None = None
    logical_operation_id: str | None = None


@dataclass(frozen=True)
class DependencyState:
    identity_available: bool = True
    policy_available: bool = True
    telemetry_available: bool = True
    effects_enabled: bool = True


@dataclass(frozen=True)
class EffectGrant:
    grant_id: str
    subject: str
    tenant: str
    operation: Operation
    resource_id: str
    request_digest: str
    policy_version: str
    expires_at: datetime
    signature: str


@dataclass(frozen=True)
class BoundaryDecision:
    request_id: str
    boundary_id: str
    allowed: bool
    reason: str
    subject: str
    tenant: str
    operation: str
    policy_version: str
    resource_digest: str
    evidence_count: int


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    kind: CaseKind
    expected_allowed: bool
    decision: BoundaryDecision


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    negative_cases: int
    attack_cases: int
    dependency_failure_cases: int
    valid_cases: int
    unexpected_allow_rate: float
    valid_task_success_rate: float
    trace_completeness_rate: float
    inventory_coverage: float
    observed_boundary_coverage: float
    observed_boundaries: int
    expected_boundaries: int


def _digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()[:16]


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def request_digest(request: BoundaryRequest) -> str:
    payload = {
        "boundary": request.boundary_id,
        "operation": request.operation.value,
        "resource": request.resource_id,
        "tenant": request.resource_tenant,
        "content_digest": request.content_digest,
        "evidence_ids": request.evidence_ids,
        "provenance_verified": request.provenance_verified,
        "logical_operation_id": request.logical_operation_id,
    }
    return sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _grant_payload(grant: EffectGrant) -> bytes:
    fields = (
        grant.grant_id,
        grant.subject,
        grant.tenant,
        grant.operation.value,
        grant.resource_id,
        grant.request_digest,
        grant.policy_version,
        grant.expires_at.isoformat(),
    )
    return "|".join(fields).encode()


def issue_demo_grant(
    request: BoundaryRequest,
    actor: ActorContext,
    *,
    grant_id: str,
    expires_at: datetime,
) -> EffectGrant:
    """Model a trusted approval service; the demo HMAC is not production PKI."""
    unsigned = EffectGrant(
        grant_id,
        actor.subject,
        actor.tenant,
        request.operation,
        request.resource_id,
        request_digest(request),
        POLICY_VERSION,
        expires_at,
        "",
    )
    signature = hmac.new(DEMO_GRANT_KEY, _grant_payload(unsigned), sha256).hexdigest()
    return replace(unsigned, signature=signature)


@dataclass
class GrantRegistry:
    grants: dict[str, EffectGrant]
    consumed: set[str] = field(default_factory=set)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def consume(self, grant_id: str | None, request: BoundaryRequest, actor: ActorContext, *, now: datetime) -> tuple[bool, str]:
        if not grant_id:
            return False, "effect-grant-required"
        with self._lock:
            grant = self.grants.get(grant_id)
            valid_signature = bool(
                grant
                and hmac.compare_digest(
                    grant.signature,
                    hmac.new(DEMO_GRANT_KEY, _grant_payload(replace(grant, signature="")), sha256).hexdigest(),
                )
            )
            valid = bool(
                grant
                and valid_signature
                and _is_aware(grant.expires_at)
                and _is_aware(now)
                and grant.grant_id not in self.consumed
                and grant.subject == actor.subject
                and grant.tenant == actor.tenant
                and grant.operation is request.operation
                and grant.resource_id == request.resource_id
                and grant.request_digest == request_digest(request)
                and grant.policy_version == POLICY_VERSION
                and grant.expires_at > now
            )
            if valid:
                self.consumed.add(grant.grant_id)
                return True, "effect-grant-consumed"
        return False, "invalid-or-replayed-effect-grant"


class BoundaryCatalog:
    def __init__(self, specs: list[BoundarySpec]):
        self.specs = {spec.boundary_id: spec for spec in specs}
        if len(self.specs) != len(specs):
            raise ValueError("boundary IDs must be unique")
        for spec in specs:
            if spec.source is spec.target:
                raise ValueError(f"{spec.boundary_id}: a boundary must cross zones")
            if spec.fail_mode != "closed":
                raise ValueError(f"{spec.boundary_id}: consequential crossings must fail closed")
            if not spec.enforcement_owner or spec.enforcement_owner in {"model", "agent"}:
                raise ValueError(f"{spec.boundary_id}: deterministic enforcement owner required")
            if not spec.evidence:
                raise ValueError(f"{spec.boundary_id}: observable evidence contract required")

    def audit(self, required_ids: frozenset[str]) -> dict[str, object]:
        present = set(self.specs) & required_ids
        missing = sorted(required_ids - set(self.specs))
        unexpected = sorted(set(self.specs) - required_ids)
        return {
            "present": len(present),
            "required": len(required_ids),
            "coverage": len(present) / len(required_ids) if required_ids else 1.0,
            "missing": missing,
            "unexpected": unexpected,
        }


class BoundaryController:
    """Policy enforcement point around every registered crossing."""

    def __init__(self, catalog: BoundaryCatalog, grants: GrantRegistry | None = None):
        self.catalog = catalog
        self.grants = grants or GrantRegistry({})
        self.events: list[BoundaryDecision] = []

    def _record(self, request: BoundaryRequest, actor: ActorContext, allowed: bool, reason: str) -> BoundaryDecision:
        decision = BoundaryDecision(
            request.request_id,
            request.boundary_id,
            allowed,
            reason,
            actor.subject,
            actor.tenant,
            request.operation.value,
            POLICY_VERSION,
            _digest(request.resource_id),
            len(request.evidence_ids),
        )
        self.events.append(decision)
        return decision

    def cross(
        self,
        actor: ActorContext,
        request: BoundaryRequest,
        *,
        state: DependencyState = DependencyState(),
        now: datetime,
    ) -> BoundaryDecision:
        spec = self.catalog.specs.get(request.boundary_id)
        if not state.telemetry_available:
            # The local list stands in for a trusted fallback audit channel.
            return self._record(request, actor, False, "telemetry-unavailable")
        if not state.identity_available:
            return self._record(request, actor, False, "identity-unavailable")
        if not state.policy_available:
            return self._record(request, actor, False, "policy-unavailable")
        if spec is None:
            return self._record(request, actor, False, "unregistered-boundary")
        if not actor.authenticated:
            return self._record(request, actor, False, "unauthenticated")
        if (request.source, request.target) != (spec.source, spec.target):
            return self._record(request, actor, False, "boundary-route-mismatch")
        if request.operation not in spec.allowed_operations:
            return self._record(request, actor, False, "operation-not-allowed")
        if spec.required_scope not in actor.scopes:
            return self._record(request, actor, False, "scope")
        if request.resource_tenant != actor.tenant:
            return self._record(request, actor, False, "tenant")
        if request.operation in {Operation.BUILD_CONTEXT, Operation.GENERATE_PROPOSAL} and (
            not request.provenance_verified or not request.evidence_ids
        ):
            return self._record(request, actor, False, "evidence-provenance")
        if request.operation is Operation.CREATE_TICKET:
            if not state.effects_enabled:
                return self._record(request, actor, False, "effects-disabled")
            if not request.logical_operation_id:
                return self._record(request, actor, False, "logical-operation-id-required")
            valid, reason = self.grants.consume(request.effect_grant_id, request, actor, now=now)
            if not valid:
                return self._record(request, actor, False, reason)
        # request.claimed_subject is deliberately ignored: content cannot grant authority.
        return self._record(request, actor, True, "policy-allow")

    def observed_coverage(self, required_ids: frozenset[str]) -> dict[str, object]:
        observed = {event.boundary_id for event in self.events} & required_ids
        return {
            "observed": len(observed),
            "required": len(required_ids),
            "coverage": len(observed) / len(required_ids) if required_ids else 1.0,
            "missing": sorted(required_ids - observed),
        }


REQUIRED_BOUNDARIES = frozenset({
    "B1-user-gateway",
    "B2-gateway-context",
    "B3-context-model",
    "B4-model-runtime",
    "B5-runtime-tool",
    "B6-tool-enterprise",
    "B7-runtime-memory",
    "B8-decisions-telemetry",
    "B9-operations-control",
})


def build_catalog() -> BoundaryCatalog:
    specs = [
        BoundarySpec("B1-user-gateway", Zone.EXTERNAL, Zone.APPLICATION, "request", frozenset({Operation.SUBMIT_REQUEST}), "request:submit", "api-gateway", ("request_id", "subject")),
        BoundarySpec("B2-gateway-context", Zone.APPLICATION, Zone.DATA, "evidence query", frozenset({Operation.BUILD_CONTEXT}), "evidence:read", "context-service", ("source_id", "policy_version")),
        BoundarySpec("B3-context-model", Zone.DATA, Zone.AGENT, "bounded context", frozenset({Operation.GENERATE_PROPOSAL}), "agent:invoke", "context-admission-gateway", ("evidence_ids", "context_digest")),
        BoundarySpec("B4-model-runtime", Zone.AGENT, Zone.APPLICATION, "action proposal", frozenset({Operation.PROPOSE_TICKET}), "ticket:propose", "agent-runtime", ("proposal_digest", "run_id")),
        BoundarySpec("B5-runtime-tool", Zone.APPLICATION, Zone.ENTERPRISE, "tool request", frozenset({Operation.READ_EVIDENCE, Operation.CREATE_TICKET}), "tool:invoke", "tool-policy-gateway", ("decision", "reason", "policy_version"), "effect"),
        BoundarySpec("B6-tool-enterprise", Zone.ENTERPRISE, Zone.DATA, "enterprise record", frozenset({Operation.READ_EVIDENCE, Operation.CREATE_TICKET}), "enterprise:access", "service-api", ("operation_id", "effect_state"), "effect"),
        BoundarySpec("B7-runtime-memory", Zone.APPLICATION, Zone.DATA, "memory record", frozenset({Operation.READ_MEMORY}), "memory:read", "memory-gateway", ("record_id", "tenant")),
        BoundarySpec("B8-decisions-telemetry", Zone.APPLICATION, Zone.OPERATIONS, "decision event", frozenset({Operation.EMIT_DECISION}), "telemetry:write", "telemetry-adapter", ("request_id", "reason")),
        BoundarySpec("B9-operations-control", Zone.OPERATIONS, Zone.APPLICATION, "revocation command", frozenset({Operation.REVOKE_EFFECTS}), "agent:operate", "control-plane", ("command_id", "operator")),
    ]
    return BoundaryCatalog(specs)


def request_for(
    boundary_id: str,
    operation: Operation,
    *,
    request_id: str,
    tenant: str = "north",
    resource_id: str = "case:42",
    **changes: object,
) -> BoundaryRequest:
    spec = build_catalog().specs[boundary_id]
    values: dict[str, object] = {
        "request_id": request_id,
        "boundary_id": boundary_id,
        "source": spec.source,
        "target": spec.target,
        "operation": operation,
        "resource_id": resource_id,
        "resource_tenant": tenant,
        "content_digest": _digest("synthetic-content"),
        "evidence_ids": ("evidence:7",),
        "provenance_verified": True,
    }
    values.update(changes)
    return BoundaryRequest(**values)


def unsafe_schema_only_baseline(request: BoundaryRequest) -> bool:
    """Educational anti-pattern: shape checks cannot authorize a crossing."""
    return bool(
        request.boundary_id
        and request.source is not request.target
        and request.resource_id
        and request.content_digest
    )


def evaluate_controls() -> tuple[EvaluationReport, list[BoundaryDecision]]:
    now = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
    actor = ActorContext(
        "user:7",
        "north",
        frozenset({
            "request:submit", "evidence:read", "agent:invoke", "ticket:propose",
            "tool:invoke", "enterprise:access", "memory:read", "telemetry:write", "agent:operate",
        }),
    )
    catalog = build_catalog()
    controller = BoundaryController(catalog)
    cases: list[EvaluationCase] = []

    valid = request_for("B2-gateway-context", Operation.BUILD_CONTEXT, request_id="valid-context")
    cases.append(EvaluationCase("valid same-tenant evidence", CaseKind.VALID, True, controller.cross(actor, valid, now=now)))

    cross_tenant = replace(valid, request_id="cross-tenant", resource_tenant="south")
    cases.append(EvaluationCase("cross-tenant evidence", CaseKind.ATTACK, False, controller.cross(actor, cross_tenant, now=now)))

    claimed_admin = request_for(
        "B4-model-runtime", Operation.PROPOSE_TICKET, request_id="claimed-admin", claimed_subject="admin"
    )
    limited_actor = replace(actor, scopes=frozenset({"agent:invoke"}))
    cases.append(EvaluationCase("model-claimed identity", CaseKind.ATTACK, False, controller.cross(limited_actor, claimed_admin, now=now)))

    bypass = replace(valid, request_id="direct-bypass", boundary_id="B0-direct-enterprise")
    cases.append(EvaluationCase("unregistered direct path", CaseKind.ATTACK, False, controller.cross(actor, bypass, now=now)))

    unavailable = replace(valid, request_id="policy-down")
    cases.append(EvaluationCase("policy dependency unavailable", CaseKind.DEPENDENCY_FAILURE, False, controller.cross(actor, unavailable, state=DependencyState(policy_available=False), now=now)))

    effect = request_for(
        "B5-runtime-tool", Operation.CREATE_TICKET, request_id="effect", evidence_ids=(),
        logical_operation_id="ticket:case:42:v1",
    )
    cases.append(EvaluationCase("effect without grant", CaseKind.ATTACK, False, controller.cross(actor, effect, now=now)))
    grant = issue_demo_grant(effect, actor, grant_id="grant:7", expires_at=now + timedelta(minutes=5))
    controller.grants.grants[grant.grant_id] = grant
    bound_effect = replace(effect, request_id="effect-authorized", effect_grant_id=grant.grant_id)
    # The grant is bound to request content, not its correlation ID.
    cases.append(EvaluationCase("bound effect", CaseKind.VALID, True, controller.cross(actor, bound_effect, now=now)))
    cases.append(EvaluationCase("replayed effect", CaseKind.ATTACK, False, controller.cross(actor, replace(bound_effect, request_id="effect-replay"), now=now)))

    # Exercise every declared boundary once so observed coverage has an explicit denominator.
    for spec in catalog.specs.values():
        operation = next(iter(spec.allowed_operations))
        probe = request_for(spec.boundary_id, operation, request_id=f"coverage-{spec.boundary_id}")
        controller.cross(actor, probe, now=now)

    negative_cases = [case for case in cases if not case.expected_allowed]
    attacks = [case for case in cases if case.kind is CaseKind.ATTACK]
    dependency_failures = [case for case in cases if case.kind is CaseKind.DEPENDENCY_FAILURE]
    valid_cases = [case for case in cases if case.kind is CaseKind.VALID]
    inventory = catalog.audit(REQUIRED_BOUNDARIES)
    observed = controller.observed_coverage(REQUIRED_BOUNDARIES)
    complete_events = [event for event in (case.decision for case in cases) if event.request_id and event.reason and event.policy_version]
    report = EvaluationReport(
        cases=len(cases),
        negative_cases=len(negative_cases),
        attack_cases=len(attacks),
        dependency_failure_cases=len(dependency_failures),
        valid_cases=len(valid_cases),
        unexpected_allow_rate=sum(case.decision.allowed for case in negative_cases) / len(negative_cases),
        valid_task_success_rate=sum(case.decision.allowed for case in valid_cases) / len(valid_cases),
        trace_completeness_rate=len(complete_events) / len(cases),
        inventory_coverage=float(inventory["coverage"]),
        observed_boundary_coverage=float(observed["coverage"]),
        observed_boundaries=int(observed["observed"]),
        expected_boundaries=int(observed["required"]),
    )
    return report, controller.events


def demo() -> EvaluationReport:
    report, events = evaluate_controls()
    assert report.unexpected_allow_rate == 0
    assert report.valid_task_success_rate == 1
    assert report.trace_completeness_rate == 1
    assert report.inventory_coverage == 1
    assert report.observed_boundary_coverage == 1
    assert all("synthetic-content" not in repr(event) for event in events)
    return report


if __name__ == "__main__":
    print(demo())
