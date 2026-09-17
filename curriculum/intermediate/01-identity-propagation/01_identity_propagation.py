"""
Intermediate 01 - Identity Propagation: Delegation, Down-Scoping, and the Confused Deputy.

This simulation demonstrates how to securely propagate user identity and authorized scopes
across multiple service hops, avoiding the "Confused Deputy" vulnerability where an agent's
ambient infrastructure privileges are exploited to access data a user shouldn't see.

Central Thesis: Propagate identity context, not ambient authority.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Set, Dict, Tuple, FrozenSet, Any

# ------------------------------------------------------------------------
# 1. Identity & Resource Models
# ------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    """The authoritative end user (the human) definition."""

    principal_id: str
    tenant: str
    allowed_operations: FrozenSet[str]
    allowed_resources: FrozenSet[str]


@dataclass(frozen=True)
class WorkloadIdentity:
    """The authoritative service or agent (the software) definition."""

    workload_id: str
    tenant: str


@dataclass(frozen=True)
class ResourceMeta:
    """Authoritative metadata about a requested resource."""

    resource_id: str
    tenant: str


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """
    A verified, authenticated principal context representing an end-user session.
    """

    principal_id: str
    auth_context_id: str


@dataclass(frozen=True)
class AuthenticatedWorkload:
    """
    A verified, authenticated workload context.
    This cannot be trivially forged from an ID string over public APIs.
    """

    workload_id: str
    tenant: str
    auth_context_id: str


@dataclass(frozen=True)
class AuthenticatedServiceJob:
    """Trusted scheduler context for one bounded background-work class."""

    job_id: str
    workload_id: str
    tenant: str
    allowed_operations: FrozenSet[str]
    allowed_resources: FrozenSet[str]
    auth_context_id: str


class ApplicationIdentityProvider:
    """
    Simulates front-door user authentication (e.g., Okta, Entra ID, web session).
    """

    _issued_contexts: Dict[str, AuthenticatedPrincipal] = {
        "ctx-alice": AuthenticatedPrincipal("alice", "ctx-alice"),
        "ctx-bob": AuthenticatedPrincipal("bob", "ctx-bob"),
        "ctx-mallory": AuthenticatedPrincipal("mallory", "ctx-mallory"),
    }

    @staticmethod
    def for_alice() -> AuthenticatedPrincipal:
        return ApplicationIdentityProvider._issued_contexts["ctx-alice"]

    @staticmethod
    def for_bob() -> AuthenticatedPrincipal:
        return ApplicationIdentityProvider._issued_contexts["ctx-bob"]

    @staticmethod
    def for_mallory() -> AuthenticatedPrincipal:
        return ApplicationIdentityProvider._issued_contexts["ctx-mallory"]

    @classmethod
    def verify(cls, context: Any) -> bool:
        if not isinstance(context, AuthenticatedPrincipal):
            return False
        canonical = cls._issued_contexts.get(context.auth_context_id)
        # Copying public claims does not recreate authentication evidence. The
        # for_* helpers simulate trusted middleware injection, not login APIs.
        return canonical is context


class InfrastructureIdentityProvider:
    """
    Simulates infrastructure-level mutual TLS or workload identity verification.
    """

    _issued_contexts: Dict[str, AuthenticatedWorkload] = {
        "ctx-research": AuthenticatedWorkload("research-agent", "acme", "ctx-research"),
        "ctx-doc": AuthenticatedWorkload("document-service", "acme", "ctx-doc"),
        "ctx-storage": AuthenticatedWorkload("storage-service", "acme", "ctx-storage"),
        "ctx-evil": AuthenticatedWorkload("evil-agent", "globex", "ctx-evil"),
    }

    @staticmethod
    def for_research_agent() -> AuthenticatedWorkload:
        return InfrastructureIdentityProvider._issued_contexts["ctx-research"]

    @staticmethod
    def for_document_service() -> AuthenticatedWorkload:
        return InfrastructureIdentityProvider._issued_contexts["ctx-doc"]

    @staticmethod
    def for_storage_service() -> AuthenticatedWorkload:
        return InfrastructureIdentityProvider._issued_contexts["ctx-storage"]

    @staticmethod
    def for_evil_agent() -> AuthenticatedWorkload:
        return InfrastructureIdentityProvider._issued_contexts["ctx-evil"]

    @classmethod
    def verify(cls, context: Any) -> bool:
        if not isinstance(context, AuthenticatedWorkload):
            return False
        canonical = cls._issued_contexts.get(context.auth_context_id)
        # A value-equivalent dataclass is still caller-constructed data. Only the
        # canonical context injected by the simulated infrastructure is trusted.
        return canonical is context


class ServiceJobIdentityProvider:
    """Simulates trusted scheduler authentication for non-request work."""

    _issued_contexts: Dict[str, AuthenticatedServiceJob] = {
        "ctx-job-doc-maintenance": AuthenticatedServiceJob(
            job_id="document-maintenance",
            workload_id="document-service",
            tenant="acme",
            allowed_operations=frozenset({"read"}),
            allowed_resources=frozenset({"doc-101", "doc-102"}),
            auth_context_id="ctx-job-doc-maintenance",
        )
    }

    @staticmethod
    def for_document_maintenance() -> AuthenticatedServiceJob:
        """Trusted-fixture seam standing in for scheduler injection."""
        return ServiceJobIdentityProvider._issued_contexts["ctx-job-doc-maintenance"]

    @classmethod
    def verify(cls, context: Any) -> bool:
        if not isinstance(context, AuthenticatedServiceJob):
            return False
        canonical = cls._issued_contexts.get(context.auth_context_id)
        return canonical is context


# ------------------------------------------------------------------------
# 2. Delegation Tokens & Audit
# ------------------------------------------------------------------------


@dataclass(frozen=True)
class DelegationGrant:
    """
    A deterministic simulation of a delegation credential (e.g., OAuth token, capability token).
    It binds a principal to a delegate, restricted by audience, scope, tenant, and time.
    """

    grant_id: str
    parent_grant_id: Optional[str]
    principal_id: str
    delegate_id: str
    tenant: str
    audience: str
    allowed_operations: FrozenSet[str]
    allowed_resources: FrozenSet[str]
    issued_at: datetime
    expires_at: datetime
    issuer: str
    delegation_depth: int = 1


@dataclass
class GrantRecord:
    """Issuer-side lifecycle state for an otherwise immutable grant."""

    grant: DelegationGrant
    active: bool = True
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class GrantIssueResult:
    grant: Optional[DelegationGrant]
    reason: str


@dataclass(frozen=True)
class GrantExchangeResult:
    grant: Optional[DelegationGrant]
    reason: str


@dataclass(frozen=True)
class GrantRevocationResult:
    revoked_count: int
    reason: str


@dataclass(frozen=True)
class EvaluationReport:
    """Metrics computed from labelled, executed authorization cases."""

    compliant_success_rate: float
    correct_block_rate: float
    unsafe_disclosure_count: int
    valid_work_block_count: int
    trace_completeness_rate: float


@dataclass
class AuditEvent:
    correlation_id: str
    principal_id: Optional[str]
    workload_id: str
    delegation_id: Optional[str]
    parent_delegation_id: Optional[str]
    audience: str
    operation: str
    resource_id: str
    decision: str
    reason: str
    delegation_depth: int
    lifecycle_state: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {"timestamp": self.occurred_at.isoformat(), **{key: value for key, value in self.__dict__.items() if key != "occurred_at"}}


class AuditSink:
    def __init__(self):
        self._events: List[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> Tuple[AuditEvent, ...]:
        return tuple(self._events)


@dataclass(frozen=True)
class ResearchResponse:
    terminal_state: str
    answer: Optional[str]
    correlation_id: str


# ------------------------------------------------------------------------
# 3. Authoritative Registries
# ------------------------------------------------------------------------

# In a real app, these come from Identity Providers, Directories, or Databases.
PRINCIPAL_REGISTRY: Dict[str, Principal] = {
    "alice": Principal("alice", "acme", frozenset({"read", "comment"}), frozenset({"doc-101", "doc-102"})),
    "bob": Principal("bob", "acme", frozenset({"read"}), frozenset({"doc-103"})),
    "mallory": Principal("mallory", "globex", frozenset({"read"}), frozenset({"doc-globex-01"})),
}

WORKLOAD_REGISTRY: Dict[str, WorkloadIdentity] = {
    "research-agent": WorkloadIdentity("research-agent", "acme"),
    "document-service": WorkloadIdentity("document-service", "acme"),
    "storage-service": WorkloadIdentity("storage-service", "acme"),
    "evil-agent": WorkloadIdentity("evil-agent", "globex"),
}

RESOURCE_REGISTRY: Dict[str, ResourceMeta] = {
    "doc-101": ResourceMeta("doc-101", "acme"),
    "doc-102": ResourceMeta("doc-102", "acme"),
    "doc-103": ResourceMeta("doc-103", "acme"),
    "doc-secret": ResourceMeta("doc-secret", "acme"),  # Not allowed to Alice or Bob
    "doc-globex-01": ResourceMeta("doc-globex-01", "globex"),
}

# The actual document contents stored in the Storage Service
DOCUMENT_STORE: Dict[str, str] = {
    "doc-101": "Public roadmap for Acme.",
    "doc-102": "Draft Q3 financials.",
    "doc-103": "Bob's private notes.",
    "doc-secret": "Acme acquisition plans.",
    "doc-globex-01": "Globex evil schemes.",
}

# ------------------------------------------------------------------------
# 4. Delegation Service (Token Issuer & Verifier)
# ------------------------------------------------------------------------


class DelegationService:
    def __init__(self, clock_fn=lambda: datetime.now(timezone.utc), max_delegation_depth: int = 2):
        if max_delegation_depth < 1:
            raise ValueError("max_delegation_depth must be at least 1")
        self._store: Dict[str, GrantRecord] = {}
        self._counter = 1
        self._clock_fn = clock_fn
        self.issuer = "acme-sts"
        self.max_delegation_depth = max_delegation_depth

    def issue(
        self,
        principal_context: AuthenticatedPrincipal,
        delegate_context: AuthenticatedWorkload,
        audience: str,
        requested_operations: Set[str],
        requested_resources: Set[str],
        ttl_minutes: int = 60,
    ) -> GrantIssueResult:
        """Issue a grant, resolving identities authoritatively and enforcing boundaries."""

        if ttl_minutes <= 0:
            return GrantIssueResult(None, "invalid_ttl")

        # 1. Authenticate at the issuer boundary, then derive claims from the
        # trusted contexts. Caller-supplied identifiers are never evidence.
        if not ApplicationIdentityProvider.verify(principal_context):
            return GrantIssueResult(None, "unauthenticated_principal")

        if not InfrastructureIdentityProvider.verify(delegate_context):
            return GrantIssueResult(None, "unauthenticated_delegate")

        principal = PRINCIPAL_REGISTRY.get(principal_context.principal_id)
        if not principal:
            return GrantIssueResult(None, "unknown_principal")

        delegate = WORKLOAD_REGISTRY.get(delegate_context.workload_id)
        if not delegate:
            return GrantIssueResult(None, "unknown_delegate")

        if delegate.tenant != delegate_context.tenant:
            return GrantIssueResult(None, "authenticated_delegate_mismatch")

        aud_workload = WORKLOAD_REGISTRY.get(audience)
        if not aud_workload:
            return GrantIssueResult(None, "unknown_audience")

        # 2. Enforce monotonic down-scoping during issuance
        if not requested_operations.issubset(principal.allowed_operations):
            return GrantIssueResult(None, "operation_not_owned")

        if not requested_resources.issubset(principal.allowed_resources):
            return GrantIssueResult(None, "resource_not_owned")

        # 3. Enforce tenant boundaries
        if principal.tenant != delegate.tenant or principal.tenant != aud_workload.tenant:
            return GrantIssueResult(None, "tenant_mismatch")

        now = self._clock_fn()
        grant_id = f"grant-{self._counter}"
        self._counter += 1

        grant = DelegationGrant(
            grant_id=grant_id,
            parent_grant_id=None,
            principal_id=principal.principal_id,
            delegate_id=delegate.workload_id,
            tenant=principal.tenant,
            audience=audience,
            allowed_operations=frozenset(requested_operations),
            allowed_resources=frozenset(requested_resources),
            issued_at=now,
            expires_at=now + timedelta(minutes=ttl_minutes),
            issuer=self.issuer,
            delegation_depth=1,
        )
        self._store[grant_id] = GrantRecord(grant)
        return GrantIssueResult(grant, "success")

    def exchange(
        self,
        parent_grant: DelegationGrant,
        current_workload: AuthenticatedWorkload,
        next_audience: str,
        requested_operations: Set[str],
        requested_resources: Set[str],
        requested_ttl_minutes: int,
    ) -> GrantExchangeResult:
        """
        Exchange a parent grant for a downstream grant, enforcing monotonic attenuation
        of scope and expiry.
        """
        if requested_ttl_minutes <= 0:
            return GrantExchangeResult(None, "invalid_ttl")

        now = self._clock_fn()

        # 0. Canonical Workload Validation
        if not InfrastructureIdentityProvider.verify(current_workload):
            return GrantExchangeResult(None, "unauthenticated_workload")

        canonical_workload = WORKLOAD_REGISTRY.get(current_workload.workload_id)
        if not canonical_workload or canonical_workload.tenant != current_workload.tenant:
            return GrantExchangeResult(None, "authenticated_workload_mismatch")

        # 1. Verify Parent Grant
        parent_record = self._store.get(parent_grant.grant_id)
        if not parent_record or parent_record.grant != parent_grant:
            return GrantExchangeResult(None, "unknown_parent_grant")

        if not parent_record.active:
            return GrantExchangeResult(None, "parent_revoked")

        if now < parent_grant.issued_at:
            return GrantExchangeResult(None, "parent_not_yet_valid")

        if now >= parent_grant.expires_at:
            return GrantExchangeResult(None, "parent_expired")

        lineage = self._validate_lineage(parent_grant)
        if not lineage.allowed:
            return GrantExchangeResult(None, f"parent_{lineage.reason}")

        if parent_grant.audience != current_workload.workload_id:
            return GrantExchangeResult(None, "current_workload_not_audience")

        if parent_grant.delegation_depth >= self.max_delegation_depth:
            return GrantExchangeResult(None, "maximum_delegation_depth_exceeded")

        # 2. Validate Audience
        next_workload = WORKLOAD_REGISTRY.get(next_audience)
        if not next_workload or next_workload.tenant != parent_grant.tenant:
            return GrantExchangeResult(None, "cross_tenant_exchange")

        # 3. Scope subset checks
        if not requested_operations.issubset(parent_grant.allowed_operations):
            return GrantExchangeResult(None, "operation_expansion")

        if not requested_resources.issubset(parent_grant.allowed_resources):
            return GrantExchangeResult(None, "resource_expansion")

        # 4. Expiry clamping (never outlive parent)
        requested_expires_at = now + timedelta(minutes=requested_ttl_minutes)
        child_expires_at = min(requested_expires_at, parent_grant.expires_at)

        grant_id = f"grant-{self._counter}"
        self._counter += 1

        grant = DelegationGrant(
            grant_id=grant_id,
            parent_grant_id=parent_grant.grant_id,
            principal_id=parent_grant.principal_id,
            delegate_id=current_workload.workload_id,
            tenant=parent_grant.tenant,
            audience=next_audience,
            allowed_operations=frozenset(requested_operations),
            allowed_resources=frozenset(requested_resources),
            issued_at=now,
            expires_at=child_expires_at,
            issuer=self.issuer,
            delegation_depth=parent_grant.delegation_depth + 1,
        )
        self._store[grant_id] = GrantRecord(grant)
        return GrantExchangeResult(grant, "success")

    def revoke_lineage(self, grant_id: str, reason: str) -> GrantRevocationResult:
        """Revoke a grant and every issued descendant in this stateful teaching STS."""
        if not reason.strip():
            return GrantRevocationResult(0, "reason_required")
        if grant_id not in self._store:
            return GrantRevocationResult(0, "unknown_delegation")

        now = self._clock_fn()
        pending = [grant_id]
        revoked = 0
        while pending:
            current_id = pending.pop()
            record = self._store[current_id]
            if record.active:
                record.active = False
                record.revoked_at = now
                record.revocation_reason = reason
                revoked += 1
            pending.extend(
                candidate_id
                for candidate_id, candidate in self._store.items()
                if candidate.grant.parent_grant_id == current_id
            )
        return GrantRevocationResult(revoked, "revoked")

    def _validate_lineage(self, grant: DelegationGrant) -> AuthorizationDecision:
        """Validate issuer-owned state for this grant and every ancestor."""
        current = grant
        seen: Set[str] = set()
        while True:
            if current.grant_id in seen:
                return AuthorizationDecision(False, "lineage_cycle")
            seen.add(current.grant_id)

            record = self._store.get(current.grant_id)
            if not record or record.grant != current:
                return AuthorizationDecision(False, "unknown_delegation")
            if current.issuer != self.issuer:
                return AuthorizationDecision(False, "issuer_mismatch")
            if not record.active:
                return AuthorizationDecision(False, "revoked")
            if current.parent_grant_id is None:
                if current.delegation_depth != 1:
                    return AuthorizationDecision(False, "invalid_delegation_depth")
                return AuthorizationDecision(True, "active")

            parent_record = self._store.get(current.parent_grant_id)
            if not parent_record:
                return AuthorizationDecision(False, "missing_parent")
            parent = parent_record.grant
            if current.delegation_depth != parent.delegation_depth + 1:
                return AuthorizationDecision(False, "invalid_delegation_depth")
            if current.principal_id != parent.principal_id or current.tenant != parent.tenant:
                return AuthorizationDecision(False, "lineage_identity_mismatch")
            current = parent

    def verify(
        self, grant: DelegationGrant, expected_delegate_id: str, expected_audience: str, expected_tenant: str, operation: str, resource_id: str
    ) -> AuthorizationDecision:
        """
        Verify the authenticity and validity of the grant for use.
        Note: We do not separately verify expected_principal_id. The principal claim
        is trusted entirely because the authentic, unexpired grant issued by
        our trusted issuer binds that principal to these permissions.
        """

        now = self._clock_fn()

        # 1. Check authenticity
        record = self._store.get(grant.grant_id)
        if not record or record.grant != grant:
            return AuthorizationDecision(False, "unknown_delegation")

        lineage = self._validate_lineage(grant)
        if not lineage.allowed:
            return AuthorizationDecision(False, lineage.reason)

        # 2. Check validity window (exact expiry boundary)
        if now < grant.issued_at:
            return AuthorizationDecision(False, "delegation_not_yet_valid")

        if now >= grant.expires_at:
            return AuthorizationDecision(False, "delegation_expired")

        # 3. Check Delegate Binding
        if grant.delegate_id != expected_delegate_id:
            return AuthorizationDecision(False, "delegate_mismatch")

        # 4. Check Audience Restriction
        if grant.audience != expected_audience:
            return AuthorizationDecision(False, "audience_mismatch")

        # 5. Check Tenant Binding
        if grant.tenant != expected_tenant:
            return AuthorizationDecision(False, "tenant_mismatch")

        # 7. Enforce Operation Scope
        if operation not in grant.allowed_operations:
            return AuthorizationDecision(False, "operation_not_delegated")

        # 8. Enforce Resource Scope
        if resource_id not in grant.allowed_resources:
            return AuthorizationDecision(False, "resource_not_delegated")

        return AuthorizationDecision(True, "allow")


# ------------------------------------------------------------------------
# 5. Storage Service (Deepest Hop)
# ------------------------------------------------------------------------


class StorageService:
    """The lowest level service. It exposes both naive and secure endpoints."""

    def __init__(self, delegation_service: DelegationService, audit_sink: AuditSink, authenticated_identity: AuthenticatedWorkload):
        if not InfrastructureIdentityProvider.verify(authenticated_identity):
            raise ValueError("invalid authenticated workload context")
        if authenticated_identity.workload_id != "storage-service":
            raise ValueError("invalid workload identity for StorageService")
        self.ds = delegation_service
        self.audit = audit_sink
        self.workload = authenticated_identity

    def read_object_naive(self, caller: AuthenticatedWorkload, resource_id: str, correlation_id: str) -> Optional[str]:
        """
        Ambient authority endpoint. If the caller is valid, give them the document.
        Simulates naive service-to-service calls bypassing user delegation.
        """
        if not caller:
            return None
        return DOCUMENT_STORE.get(resource_id)

    def read_object(
        self, caller: AuthenticatedWorkload, grant: Optional[DelegationGrant], resource_id: str, correlation_id: str, depth: int = 2
    ) -> Optional[str]:
        """Request-facing delegated endpoint. It has no service-mode switch."""
        # 1. Validate caller identity
        if not InfrastructureIdentityProvider.verify(caller):
            self._audit(
                correlation_id,
                None,
                getattr(caller, "workload_id", "unknown"),
                grant,
                "read",
                resource_id,
                "DENY",
                "unauthenticated_workload",
                depth,
                "blocked",
            )
            return None

        # 2. Check resource existence and ownership
        resource = RESOURCE_REGISTRY.get(resource_id)
        if not resource:
            self._audit(correlation_id, None, caller.workload_id, grant, "read", resource_id, "DENY", "unknown_resource", depth, "blocked")
            return None

        # 3. Authorize via Delegation
        if not grant:
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "missing_delegation", depth, "blocked")
            return None

        decision = self.ds.verify(
            grant=grant,
            expected_delegate_id=caller.workload_id,
            expected_audience=self.workload.workload_id,
            expected_tenant=resource.tenant,
            operation="read",
            resource_id=resource.resource_id,
        )

        if not decision.allowed:
            # MUST NOT fallback to read_object_naive
            self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "DENY", decision.reason, depth, "blocked")
            return None

        # Success
        self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "ALLOW", "success", depth, "accessed")
        return DOCUMENT_STORE.get(resource_id)

    def read_object_for_service(
        self, caller: AuthenticatedWorkload, job_context: AuthenticatedServiceJob, resource_id: str, correlation_id: str, depth: int = 2
    ) -> Optional[str]:
        """Internal service-only endpoint, distinct from delegated requests."""
        if not InfrastructureIdentityProvider.verify(caller):
            self._audit(
                correlation_id,
                None,
                getattr(caller, "workload_id", "unknown"),
                None,
                "read",
                resource_id,
                "DENY",
                "unauthenticated_service_workload",
                depth,
                "blocked",
            )
            return None
        if caller.workload_id != "document-service":
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "service_workload_not_allowed", depth, "blocked")
            return None
        if not ServiceJobIdentityProvider.verify(job_context):
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "unauthenticated_service_job", depth, "blocked")
            return None
        if job_context.workload_id != caller.workload_id or job_context.tenant != caller.tenant:
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "service_job_identity_mismatch", depth, "blocked")
            return None
        if "read" not in job_context.allowed_operations or resource_id not in job_context.allowed_resources:
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "service_job_scope_violation", depth, "blocked")
            return None

        resource = RESOURCE_REGISTRY.get(resource_id)
        if not resource:
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "unknown_resource", depth, "not_found")
            return None
        if resource.tenant != caller.tenant:
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "tenant_mismatch", depth, "blocked")
            return None

        value = DOCUMENT_STORE.get(resource_id)
        if value is None:
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "resource_missing", depth, "not_found")
            return None

        self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "ALLOW", "service_identity_authorized", depth, "accessed")
        return value

    def _audit(self, cid, pid, wid, grant, op, res, decision, reason, depth, lifecycle):
        self.audit.record(
            AuditEvent(
                cid,
                pid,
                wid,
                grant.grant_id if grant else None,
                grant.parent_grant_id if grant else None,
                self.workload.workload_id,
                op,
                res,
                decision,
                reason,
                depth,
                lifecycle,
            )
        )


# ------------------------------------------------------------------------
# 6. Document Services (The Deputies)
# ------------------------------------------------------------------------


class NaiveDocumentService:
    """
    VULNERABLE: Confused Deputy.
    This service accepts the agent's workload identity as sufficient authorization,
    ignoring the user entirely. It uses ambient authority to query the backend.
    """

    def __init__(self, storage: StorageService, authenticated_identity: AuthenticatedWorkload):
        self.storage = storage
        self.workload = authenticated_identity

    def get_document(self, caller: AuthenticatedWorkload, resource_id: str, correlation_id: str) -> Optional[str]:
        # Agent claims to be authorized, and it is a trusted internal service!
        if caller and caller.workload_id == "research-agent":
            # Authenticate Document Service to Storage Service
            return self.storage.read_object_naive(self.workload, resource_id, correlation_id)
        return None


class SecureDocumentService:
    """
    SECURE: Identity Propagation.
    This service verifies the incoming grant, then explicitly down-scopes and
    exchanges the grant for a new one destined for the Storage Service.
    """

    def __init__(self, delegation_service: DelegationService, storage: StorageService, audit_sink: AuditSink, authenticated_identity: AuthenticatedWorkload):
        if not InfrastructureIdentityProvider.verify(authenticated_identity):
            raise ValueError("invalid authenticated workload context")
        if authenticated_identity.workload_id != "document-service":
            raise ValueError("invalid workload identity for SecureDocumentService")
        self.ds = delegation_service
        self.storage = storage
        self.audit = audit_sink
        self.workload = authenticated_identity

    def get_document(
        self, caller: AuthenticatedWorkload, grant: Optional[DelegationGrant], resource_id: str, correlation_id: str, depth: int = 1
    ) -> Optional[str]:
        """Request-facing delegated endpoint. Delegation is always required."""
        # 1. Resolve Workload
        if not InfrastructureIdentityProvider.verify(caller):
            self._audit(
                correlation_id,
                None,
                getattr(caller, "workload_id", "unknown"),
                grant,
                "read",
                resource_id,
                "DENY",
                "unauthenticated_workload",
                depth,
                "blocked",
            )
            return None

        # 2. Resource tenant resolution
        resource = RESOURCE_REGISTRY.get(resource_id)
        if not resource:
            self._audit(correlation_id, None, caller.workload_id, grant, "read", resource_id, "DENY", "unknown_resource", depth, "blocked")
            return None

        if not grant:
            self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "DENY", "missing_delegation", depth, "blocked")
            return None

        # 3. Verify incoming delegation
        decision = self.ds.verify(
            grant=grant,
            expected_delegate_id=caller.workload_id,
            expected_audience=self.workload.workload_id,
            expected_tenant=resource.tenant,
            operation="read",
            resource_id=resource_id,
        )

        if not decision.allowed:
            self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "DENY", decision.reason, depth, "blocked")
            return None

        self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "ALLOW", "propagating_downstream", depth, "forwarded")

        # 4. Multi-hop Down-scoping (Token Exchange)
        exchange_result = self.ds.exchange(
            parent_grant=grant,
            current_workload=self.workload,
            next_audience="storage-service",
            requested_operations={"read"},
            requested_resources={resource_id},
            requested_ttl_minutes=5,  # Tighter expiry for downstream
        )

        if not exchange_result.grant:
            self._audit(
                correlation_id,
                grant.principal_id,
                caller.workload_id,
                grant,
                "read",
                resource_id,
                "DENY",
                f"exchange_failed: {exchange_result.reason}",
                depth,
                "blocked",
            )
            return None

        # 5. Call downstream StorageService with the new Down-scoped Grant
        return self.storage.read_object(
            caller=self.workload, grant=exchange_result.grant, resource_id=resource_id, correlation_id=correlation_id, depth=depth + 1
        )

    def run_service_read(self, job_context: AuthenticatedServiceJob, resource_id: str, correlation_id: str, depth: int = 1) -> Optional[str]:
        """Internal background-work entry point, never selected by request data."""
        if not ServiceJobIdentityProvider.verify(job_context):
            self._audit(correlation_id, None, self.workload.workload_id, None, "read", resource_id, "DENY", "unauthenticated_service_job", depth, "blocked")
            return None
        if job_context.workload_id != self.workload.workload_id or job_context.tenant != self.workload.tenant:
            self._audit(correlation_id, None, self.workload.workload_id, None, "read", resource_id, "DENY", "service_job_identity_mismatch", depth, "blocked")
            return None
        return self.storage.read_object_for_service(
            caller=self.workload, job_context=job_context, resource_id=resource_id, correlation_id=correlation_id, depth=depth + 1
        )

    def _audit(self, cid, pid, wid, grant, op, res, decision, reason, depth, lifecycle):
        self.audit.record(
            AuditEvent(
                cid,
                pid,
                wid,
                grant.grant_id if grant else None,
                grant.parent_grant_id if grant else None,
                self.workload.workload_id,
                op,
                res,
                decision,
                reason,
                depth,
                lifecycle,
            )
        )


# ------------------------------------------------------------------------
# 7. Agent & Application
# ------------------------------------------------------------------------


class ResearchAgent:
    def __init__(
        self, document_service: SecureDocumentService, authenticated_identity: AuthenticatedWorkload, naive_service: Optional[NaiveDocumentService] = None
    ):
        if not InfrastructureIdentityProvider.verify(authenticated_identity):
            raise ValueError("invalid authenticated workload context")
        if authenticated_identity.workload_id != "research-agent":
            raise ValueError("invalid workload identity for ResearchAgent")
        self.doc_service = document_service
        self.naive_service = naive_service
        self.workload = authenticated_identity

    def read_naive(self, requested_doc: str, correlation_id: str) -> Optional[str]:
        if not self.naive_service:
            return None
        return self.naive_service.get_document(self.workload, requested_doc, correlation_id)

    def read_secure(self, grant: DelegationGrant, requested_doc: str, correlation_id: str) -> Optional[str]:
        return self.doc_service.get_document(caller=self.workload, grant=grant, resource_id=requested_doc, correlation_id=correlation_id)


class ResearchApplication:
    """Public delegated API boundary with server-issued request identifiers."""

    def __init__(
        self,
        ds: DelegationService,
        doc_service: SecureDocumentService,
        authenticated_agent: AuthenticatedWorkload,
        naive_service: Optional[NaiveDocumentService] = None,
        audit_sink: Optional[AuditSink] = None,
    ):
        self.ds = ds
        self.agent = ResearchAgent(doc_service, authenticated_agent, naive_service)
        self.audit = audit_sink or AuditSink()
        self._request_counter = 1

    def _new_correlation_id(self) -> str:
        correlation_id = f"request-{self._request_counter}"
        self._request_counter += 1
        return correlation_id

    def answer_naive(self, subject: Any, document_id: str, correlation_id: Optional[str] = None) -> str:
        """DEMO-ONLY confused-deputy baseline. Never expose this path in production."""
        correlation_id = correlation_id or self._new_correlation_id()
        res = self.agent.read_naive(document_id, correlation_id)
        if res:
            return f"Found document {document_id}: {res}"
        return "Not found."

    def answer_secure(
        self,
        principal_context: AuthenticatedPrincipal,
        document_id: str,
        correlation_id: Optional[str] = None,
    ) -> ResearchResponse:
        correlation_id = correlation_id or self._new_correlation_id()
        if not ApplicationIdentityProvider.verify(principal_context):
            pid = getattr(principal_context, "principal_id", "unknown")
            self.audit.record(
                AuditEvent(
                    correlation_id, pid, "research-agent", None, None, "research-agent", "read", document_id, "DENY", "unauthenticated_principal", 0, "blocked"
                )
            )
            return ResearchResponse("blocked", "Access denied.", correlation_id)

        principal = PRINCIPAL_REGISTRY.get(principal_context.principal_id)
        if not principal:
            self.audit.record(
                AuditEvent(
                    correlation_id,
                    principal_context.principal_id,
                    "research-agent",
                    None,
                    None,
                    "research-agent",
                    "read",
                    document_id,
                    "DENY",
                    "unknown_principal",
                    0,
                    "blocked",
                )
            )
            return ResearchResponse("blocked", "Access denied.", correlation_id)

        # Issue a tightly scoped grant for this specific operation
        issue_result = self.ds.issue(
            principal_context=principal_context,
            delegate_context=self.agent.workload,
            audience="document-service",
            requested_operations={"read"},
            requested_resources={document_id},
        )

        if not issue_result.grant:
            self.audit.record(
                AuditEvent(
                    correlation_id,
                    principal_context.principal_id,
                    "research-agent",
                    None,
                    None,
                    "document-service",
                    "read",
                    document_id,
                    "DENY",
                    f"issuance_failed: {issue_result.reason}",
                    0,
                    "blocked",
                )
            )
            return ResearchResponse("blocked", "Access denied.", correlation_id)

        res = self.agent.read_secure(issue_result.grant, document_id, correlation_id)

        if res:
            return ResearchResponse("answered", f"Found document {document_id}: {res}", correlation_id)
        return ResearchResponse("insufficient_evidence", "I cannot answer this based on authorized available evidence.", correlation_id)


def evaluate_security_controls() -> EvaluationReport:
    """Execute labelled allow/deny cases and derive security and utility metrics."""
    clock = lambda: datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    ds = DelegationService(clock_fn=clock)
    audit = AuditSink()
    storage = StorageService(ds, audit, InfrastructureIdentityProvider.for_storage_service())
    documents = SecureDocumentService(
        ds,
        storage,
        audit,
        InfrastructureIdentityProvider.for_document_service(),
    )
    app = ResearchApplication(
        ds,
        documents,
        InfrastructureIdentityProvider.for_research_agent(),
        audit_sink=audit,
    )

    labelled_cases = (
        ("allowed_alice_document", ApplicationIdentityProvider.for_alice(), "doc-101", True),
        ("blocked_unowned_document", ApplicationIdentityProvider.for_alice(), "doc-secret", False),
        ("blocked_cross_tenant", ApplicationIdentityProvider.for_mallory(), "doc-globex-01", False),
    )
    valid_total = blocked_total = valid_success = correct_blocks = unsafe_disclosures = 0
    complete_traces = 0

    for case_id, principal, resource_id, expected_allow in labelled_cases:
        response = app.answer_secure(principal, resource_id, f"eval-{case_id}")
        allowed = response.terminal_state == "answered"
        events = [event for event in audit.events if event.correlation_id == f"eval-{case_id}"]
        trace_complete = bool(events) and all(
            event.correlation_id
            and event.workload_id
            and event.audience
            and event.operation
            and event.resource_id
            and event.decision in {"ALLOW", "DENY"}
            for event in events
        )
        complete_traces += int(trace_complete)
        if expected_allow:
            valid_total += 1
            valid_success += int(allowed)
        else:
            blocked_total += 1
            correct_blocks += int(not allowed)
            unsafe_disclosures += int(allowed)

    return EvaluationReport(
        compliant_success_rate=valid_success / valid_total,
        correct_block_rate=correct_blocks / blocked_total,
        unsafe_disclosure_count=unsafe_disclosures,
        valid_work_block_count=valid_total - valid_success,
        trace_completeness_rate=complete_traces / len(labelled_cases),
    )


# ------------------------------------------------------------------------
# 8. Adversarial Demonstration
# ------------------------------------------------------------------------
def run_demo():
    print("=== Intermediate 01: Identity Propagation ===\n")

    clock = lambda: datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
    ds = DelegationService(clock_fn=clock)
    audit = AuditSink()

    # 0. Infrastructure bootstraps application with identities
    auth_alice = ApplicationIdentityProvider.for_alice()
    auth_bob = ApplicationIdentityProvider.for_bob()
    auth_mallory = ApplicationIdentityProvider.for_mallory()

    auth_agent = InfrastructureIdentityProvider.for_research_agent()
    auth_doc = InfrastructureIdentityProvider.for_document_service()
    auth_storage = InfrastructureIdentityProvider.for_storage_service()
    auth_job = ServiceJobIdentityProvider.for_document_maintenance()

    principal_contexts = {"alice": auth_alice, "bob": auth_bob, "mallory": auth_mallory}
    workload_contexts = {
        "research-agent": auth_agent,
        "document-service": auth_doc,
        "storage-service": auth_storage,
        "evil-agent": InfrastructureIdentityProvider.for_evil_agent(),
    }

    def issue_for_demo(principal_id, delegate_id, audience, operations, resources, ttl_minutes=60):
        return ds.issue(principal_contexts[principal_id], workload_contexts[delegate_id], audience, operations, resources, ttl_minutes)

    storage = StorageService(ds, audit, auth_storage)
    secure_docs = SecureDocumentService(ds, storage, audit, auth_doc)
    naive_docs = NaiveDocumentService(storage, auth_doc)

    app = ResearchApplication(ds, secure_docs, auth_agent, naive_docs, audit)

    scenarios = []

    def log_scenario(name, result):
        scenarios.append((name, result))
        print(f"[+] {name}\n    -> {result}")

    print("--- Adversarial Scenarios ---\n")

    # 1. Valid delegated read
    res = app.answer_secure(auth_alice, "doc-101", "req-1")
    log_scenario("Valid delegated read", "Allowed" if res.terminal_state == "answered" else "Denied")

    # 2. Unauthorized user resource
    res = app.answer_secure(auth_alice, "doc-secret", "req-2")
    log_scenario("Unauthorized user resource (doc-secret)", "Blocked (issuance_failed: resource_not_owned)" if res.terminal_state == "blocked" else "Leaked")

    # 3. Resource outside grant (use-time check)
    grant_res = issue_for_demo("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
    res = secure_docs.get_document(auth_agent, grant_res.grant, "doc-102", "req-3")
    log_scenario("Resource outside grant", "Denied (resource_not_delegated)" if not res else "Allowed")

    # 4. Operation outside grant (use-time check)
    decision = ds.verify(grant_res.grant, "research-agent", "document-service", "acme", "delete", "doc-101")
    log_scenario("Operation outside grant (delete)", f"Denied ({decision.reason})" if not decision.allowed else "Allowed")

    # 5. Cross-tenant resource
    res = app.answer_secure(auth_mallory, "doc-101", "req-5")
    log_scenario("Cross-tenant resource (mallory -> acme doc)", "Blocked" if res.terminal_state == "blocked" else "Allowed")

    # 6. Fabricated grant
    fake_grant = DelegationGrant(
        "fake",
        None,
        "alice",
        "document-service",
        "acme",
        "storage-service",
        frozenset({"read"}),
        frozenset({"doc-101"}),
        clock(),
        clock() + timedelta(minutes=60),
        "hacker",
    )
    res = storage.read_object(auth_doc, fake_grant, "doc-101", "req-6")
    log_scenario("Fabricated grant", "Denied (unknown_delegation)" if not res else "Allowed")

    # 7. Expired grant
    grant_exp = issue_for_demo("alice", "document-service", "storage-service", {"read"}, {"doc-101"}, ttl_minutes=5)

    class MutableClock:
        def __init__(self, start):
            self.now = start

        def __call__(self):
            return self.now

    mc = MutableClock(clock())
    storage.ds._clock_fn = mc
    mc.now += timedelta(minutes=6)
    res = storage.read_object(auth_doc, grant_exp.grant, "doc-101", "req-7")
    storage.ds._clock_fn = clock  # reset
    log_scenario("Expired grant", "Denied (delegation_expired)" if not res else "Allowed")

    # 8. Wrong delegate
    grant_wrong = issue_for_demo("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
    res = secure_docs.get_document(auth_doc, grant_wrong.grant, "doc-101", "req-8")  # caller is document-service, but delegate is research-agent
    log_scenario("Wrong delegate", "Denied (delegate_mismatch)" if not res else "Allowed")

    # 9. Wrong audience
    grant_aud = issue_for_demo("alice", "research-agent", "storage-service", {"read"}, {"doc-101"})
    res = secure_docs.get_document(auth_agent, grant_aud.grant, "doc-101", "req-9")
    log_scenario("Wrong audience", "Denied (audience_mismatch)" if not res else "Allowed")

    # 10. Workload impersonation (missing identity)
    res = storage.read_object(None, grant_aud.grant, "doc-101", "req-10")
    log_scenario("Workload impersonation (no valid auth)", "Denied (unauthenticated_workload)" if not res else "Allowed")

    # 11. Workload impersonation (forged identity)
    forged_auth = AuthenticatedWorkload("document-service", "acme", "forged-ctx")
    exch = ds.exchange(grant_wrong.grant, forged_auth, "storage-service", {"read"}, {"doc-101"}, 10)
    log_scenario("Forged workload context", f"Denied ({exch.reason})" if not exch.grant else "Allowed")

    # 12. Ambient-authority fallback attempt
    ans = app.answer_naive("alice", "doc-secret")
    log_scenario("Ambient-authority fallback (Naive)", "Leaked" if "Acme acquisition plans" in ans else "Blocked")

    # 13. Valid multi-hop exchange
    parent = issue_for_demo("alice", "research-agent", "document-service", {"read", "comment"}, {"doc-101", "doc-102"})
    child = ds.exchange(parent.grant, auth_doc, "storage-service", {"read"}, {"doc-101"}, 10)
    log_scenario("Valid multi-hop exchange", f"Allowed (Child ID: {child.grant.grant_id})" if child.grant else "Denied")

    # 14. Scope-expansion exchange
    bad_child = ds.exchange(parent.grant, auth_doc, "storage-service", {"read", "delete"}, {"doc-101"}, 10)
    log_scenario("Scope-expansion exchange", f"Denied ({bad_child.reason})" if not bad_child.grant else "Allowed")

    # 15. Child-expiry expansion
    child_exp = ds.exchange(parent.grant, auth_doc, "storage-service", {"read"}, {"doc-101"}, 120)
    log_scenario(
        "Child-expiry expansion",
        f"Clamped ({child_exp.grant.expires_at == parent.grant.expires_at})"
        if child_exp.grant and child_exp.grant.expires_at == parent.grant.expires_at
        else "Failed",
    )

    # 16. Verify Principal Attribution Preservation
    events = [e for e in audit.events if e.correlation_id == "req-1"]
    has_alice_everywhere = all(e.principal_id == "alice" for e in events)
    log_scenario("Principal Attribution Preserved", "Yes" if has_alice_everywhere else "No")

    # 17. Principal impersonation (forged context)
    forged_alice = AuthenticatedPrincipal("alice", "forged-ctx")
    res_fake_alice = app.answer_secure(forged_alice, "doc-101", "req-17")
    log_scenario(
        "Principal impersonation (forged auth)",
        "Denied (unauthenticated_principal)"
        if res_fake_alice.terminal_state == "blocked" and "unauthenticated_principal" in str(audit.events[-1].reason)
        else "Allowed",
    )

    # 18. Principal context substitution (Alice ID + Mallory Context)
    substituted_alice = AuthenticatedPrincipal("alice", auth_mallory.auth_context_id)
    res_sub_alice = app.answer_secure(substituted_alice, "doc-101", "req-18")
    log_scenario(
        "Principal context substitution (Alice ID + Mallory Ctx)",
        "Denied (unauthenticated_principal)"
        if res_sub_alice.terminal_state == "blocked" and "unauthenticated_principal" in str(audit.events[-1].reason)
        else "Allowed",
    )

    # 19. Workload impersonation (missing ID)
    res_missing_wl = storage.read_object(None, grant_aud.grant, "doc-101", "req-19")
    log_scenario(
        "Workload impersonation (missing identity)",
        "Denied (unauthenticated_workload)" if not res_missing_wl and audit.events[-1].reason == "unauthenticated_workload" else "Allowed",
    )

    # 20. Workload impersonation (forged exact metadata)
    forged_doc = AuthenticatedWorkload("document-service", "acme", "forged-ctx")
    res_forged_wl = storage.read_object(forged_doc, grant_aud.grant, "doc-101", "req-20")
    log_scenario(
        "Workload impersonation (forged metadata)",
        "Denied (unauthenticated_workload)" if not res_forged_wl and audit.events[-1].reason == "unauthenticated_workload" else "Allowed",
    )

    # 21. Workload context substitution (Doc Service ID + Research Agent Ctx)
    substituted_doc = AuthenticatedWorkload("document-service", "acme", auth_agent.auth_context_id)
    res_sub_wl = storage.read_object(substituted_doc, grant_aud.grant, "doc-101", "req-21")
    log_scenario(
        "Workload context substitution (Doc ID + Agent Ctx)",
        "Denied (unauthenticated_workload)" if not res_sub_wl and audit.events[-1].reason == "unauthenticated_workload" else "Allowed",
    )

    # 22. Exact-copy principal context
    copied_bob = AuthenticatedPrincipal("bob", "ctx-bob")
    res_copy_principal = app.answer_secure(copied_bob, "doc-103", "req-22")
    log_scenario("Exact-copy principal context", "Denied (unauthenticated_principal)" if res_copy_principal.terminal_state == "blocked" else "Allowed")

    # 23. Exact-copy workload context
    copied_doc = AuthenticatedWorkload("document-service", "acme", "ctx-doc")
    direct_grant = issue_for_demo("alice", "document-service", "storage-service", {"read"}, {"doc-101"})
    res_copy_workload = storage.read_object(copied_doc, direct_grant.grant, "doc-101", "req-23")
    log_scenario("Exact-copy workload context", "Denied (unauthenticated_workload)" if not res_copy_workload else "Allowed")

    # 24. Request data cannot select service authority
    try:
        secure_docs.get_document(None, None, "doc-secret", "req-24", mode="service")
        mode_result = "Allowed"
    except TypeError:
        mode_result = "Denied (no request-facing mode switch)"
    log_scenario("Caller-selected service mode", mode_result)

    # 25. Trusted internal service entry point remains available
    service_result = secure_docs.run_service_read(auth_job, "doc-101", "job-25")
    log_scenario("Trusted service entry point", "Allowed and audited" if service_result else "Denied")

    print("\n--- Summary ---")
    print(f"Total Scenarios Run: {len(scenarios)}")


if __name__ == "__main__":
    run_demo()
