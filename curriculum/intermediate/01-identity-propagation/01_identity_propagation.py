"""
Intermediate 01 - Identity Propagation: Delegation, Down-Scoping, and the Confused Deputy.

This simulation demonstrates how to securely propagate user identity and authorized scopes 
across multiple service hops, avoiding the "Confused Deputy" vulnerability where an agent's 
ambient infrastructure privileges are exploited to access data a user shouldn't see.

Central Thesis: Propagate identity context, not ambient authority.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
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

class ExecutionMode(str, Enum):
    """Execution context: acting as a service itself, or on behalf of a user."""
    SERVICE = "service"
    DELEGATED = "delegated"

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

class ApplicationIdentityProvider:
    """
    Simulates front-door user authentication (e.g., Okta, Entra ID, web session).
    """
    _issued_contexts: Set[str] = {"ctx-alice", "ctx-bob", "ctx-mallory"}

    @staticmethod
    def for_alice() -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal("alice", "ctx-alice")
        
    @staticmethod
    def for_bob() -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal("bob", "ctx-bob")
        
    @staticmethod
    def for_mallory() -> AuthenticatedPrincipal:
        return AuthenticatedPrincipal("mallory", "ctx-mallory")
        
    @classmethod
    def verify(cls, context: Any) -> bool:
        return isinstance(context, AuthenticatedPrincipal) and context.auth_context_id in cls._issued_contexts

class InfrastructureIdentityProvider:
    """
    Simulates infrastructure-level mutual TLS or workload identity verification.
    """
    _issued_contexts: Set[str] = {"ctx-research", "ctx-doc", "ctx-storage", "ctx-evil"}

    @staticmethod
    def for_research_agent() -> AuthenticatedWorkload:
        return AuthenticatedWorkload("research-agent", "acme", "ctx-research")

    @staticmethod
    def for_document_service() -> AuthenticatedWorkload:
        return AuthenticatedWorkload("document-service", "acme", "ctx-doc")

    @staticmethod
    def for_storage_service() -> AuthenticatedWorkload:
        return AuthenticatedWorkload("storage-service", "acme", "ctx-storage")

    @staticmethod
    def for_evil_agent() -> AuthenticatedWorkload:
        return AuthenticatedWorkload("evil-agent", "globex", "ctx-evil")
        
    @classmethod
    def verify(cls, context: Any) -> bool:
        return isinstance(context, AuthenticatedWorkload) and context.auth_context_id in cls._issued_contexts

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

    def to_dict(self) -> dict:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **self.__dict__
        }

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
    "mallory": Principal("mallory", "globex", frozenset({"read"}), frozenset({"doc-globex-01"}))
}

WORKLOAD_REGISTRY: Dict[str, WorkloadIdentity] = {
    "research-agent": WorkloadIdentity("research-agent", "acme"),
    "document-service": WorkloadIdentity("document-service", "acme"),
    "storage-service": WorkloadIdentity("storage-service", "acme"),
    "evil-agent": WorkloadIdentity("evil-agent", "globex")
}

RESOURCE_REGISTRY: Dict[str, ResourceMeta] = {
    "doc-101": ResourceMeta("doc-101", "acme"),
    "doc-102": ResourceMeta("doc-102", "acme"),
    "doc-103": ResourceMeta("doc-103", "acme"),
    "doc-secret": ResourceMeta("doc-secret", "acme"), # Not allowed to Alice or Bob
    "doc-globex-01": ResourceMeta("doc-globex-01", "globex")
}

# The actual document contents stored in the Storage Service
DOCUMENT_STORE: Dict[str, str] = {
    "doc-101": "Public roadmap for Acme.",
    "doc-102": "Draft Q3 financials.",
    "doc-103": "Bob's private notes.",
    "doc-secret": "Acme acquisition plans.",
    "doc-globex-01": "Globex evil schemes."
}

# ------------------------------------------------------------------------
# 4. Delegation Service (Token Issuer & Verifier)
# ------------------------------------------------------------------------

class DelegationService:
    def __init__(self, clock_fn=lambda: datetime.now(timezone.utc)):
        self._store: Dict[str, DelegationGrant] = {}
        self._counter = 1
        self._clock_fn = clock_fn
        self.issuer = "acme-sts"

    def issue(
        self, 
        principal_id: str, 
        delegate_id: str, 
        audience: str, 
        requested_operations: Set[str], 
        requested_resources: Set[str],
        ttl_minutes: int = 60
    ) -> GrantIssueResult:
        """Issue a grant, resolving identities authoritatively and enforcing boundaries."""
        
        if ttl_minutes <= 0:
            return GrantIssueResult(None, "invalid_ttl")

        # 1. Resolve authoritatively
        principal = PRINCIPAL_REGISTRY.get(principal_id)
        if not principal:
            return GrantIssueResult(None, "unknown_principal")
            
        delegate = WORKLOAD_REGISTRY.get(delegate_id)
        if not delegate:
            return GrantIssueResult(None, "unknown_delegate")

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
            issuer=self.issuer
        )
        self._store[grant_id] = grant
        return GrantIssueResult(grant, "success")

    def exchange(
        self,
        parent_grant: DelegationGrant,
        current_workload: AuthenticatedWorkload,
        next_audience: str,
        requested_operations: Set[str],
        requested_resources: Set[str],
        requested_ttl_minutes: int
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
        if parent_grant.grant_id not in self._store or self._store[parent_grant.grant_id] != parent_grant:
            return GrantExchangeResult(None, "unknown_parent_grant")
            
        if now >= parent_grant.expires_at:
            return GrantExchangeResult(None, "parent_expired")
            
        if parent_grant.audience != current_workload.workload_id:
            return GrantExchangeResult(None, "current_workload_not_audience")
            
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
            issuer=self.issuer
        )
        self._store[grant_id] = grant
        return GrantExchangeResult(grant, "success")
        
    def verify(
        self, 
        grant: DelegationGrant, 
        expected_delegate_id: str, 
        expected_audience: str, 
        expected_tenant: str,
        operation: str,
        resource_id: str
    ) -> AuthorizationDecision:
        """
        Verify the authenticity and validity of the grant for use.
        Note: We do not separately verify expected_principal_id. The principal claim 
        is trusted entirely because the authentic, unexpired grant issued by 
        our trusted issuer binds that principal to these permissions.
        """
        
        now = self._clock_fn()
        
        # 1. Check authenticity
        if grant.grant_id not in self._store or self._store[grant.grant_id] != grant:
            return AuthorizationDecision(False, "unknown_delegation")
            
        # 2. Check Expiry (exact boundary)
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

    def read_object(self, caller: AuthenticatedWorkload, grant: Optional[DelegationGrant], resource_id: str, correlation_id: str, mode: ExecutionMode = ExecutionMode.DELEGATED, depth: int = 2) -> Optional[str]:
        if mode == ExecutionMode.SERVICE:
            # Service mode: Backend trusts the caller workload natively for background tasks.
            if caller and caller.workload_id == "document-service":
                self._audit(correlation_id, None, caller.workload_id, None, "read", resource_id, "ALLOW", "service_mode", depth, "accessed")
                return DOCUMENT_STORE.get(resource_id)
            self._audit(correlation_id, None, caller.workload_id if caller else "unknown", None, "read", resource_id, "DENY", "service_mode_unauthorized", depth, "blocked")
            return None

        # Delegated mode requires delegation grant. No fallback to service mode.
        # 1. Validate caller identity
        if not InfrastructureIdentityProvider.verify(caller):
            self._audit(correlation_id, None, getattr(caller, "workload_id", "unknown"), grant, "read", resource_id, "DENY", "unauthenticated_workload", depth, "blocked")
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
            resource_id=resource.resource_id
        )
        
        if not decision.allowed:
            # MUST NOT fallback to read_object_naive
            self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "DENY", decision.reason, depth, "blocked")
            return None
            
        # Success
        self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "ALLOW", "success", depth, "accessed")
        return DOCUMENT_STORE.get(resource_id)

    def _audit(self, cid, pid, wid, grant, op, res, decision, reason, depth, lifecycle):
        self.audit.record(AuditEvent(cid, pid, wid, grant.grant_id if grant else None, grant.parent_grant_id if grant else None, self.workload.workload_id, op, res, decision, reason, depth, lifecycle))


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
        self.ds = delegation_service
        self.storage = storage
        self.audit = audit_sink
        self.workload = authenticated_identity

    def get_document(self, caller: AuthenticatedWorkload, grant: Optional[DelegationGrant], resource_id: str, correlation_id: str, mode: ExecutionMode = ExecutionMode.DELEGATED, depth: int = 1) -> Optional[str]:
        if mode == ExecutionMode.SERVICE:
            # Simulate a background maintenance task
            return self.storage.read_object(self.workload, None, resource_id, correlation_id, mode=ExecutionMode.SERVICE, depth=depth+1)
            
        # 1. Resolve Workload
        if not InfrastructureIdentityProvider.verify(caller):
            self._audit(correlation_id, None, getattr(caller, "workload_id", "unknown"), grant, "read", resource_id, "DENY", "unauthenticated_workload", depth, "blocked")
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
            resource_id=resource_id
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
            requested_ttl_minutes=5 # Tighter expiry for downstream
        )
        
        if not exchange_result.grant:
             # Should not happen unless requested out-of-bounds or fake grant
             return None

        # 5. Call downstream StorageService with the new Down-scoped Grant
        return self.storage.read_object(
            caller=self.workload,
            grant=exchange_result.grant,
            resource_id=resource_id,
            correlation_id=correlation_id,
            mode=ExecutionMode.DELEGATED,
            depth=depth + 1
        )

    def _audit(self, cid, pid, wid, grant, op, res, decision, reason, depth, lifecycle):
        self.audit.record(AuditEvent(cid, pid, wid, grant.grant_id if grant else None, grant.parent_grant_id if grant else None, self.workload.workload_id, op, res, decision, reason, depth, lifecycle))


# ------------------------------------------------------------------------
# 7. Agent & Application
# ------------------------------------------------------------------------

class ResearchAgent:
    def __init__(self, document_service: SecureDocumentService, authenticated_identity: AuthenticatedWorkload, naive_service: Optional[NaiveDocumentService] = None):
        self.doc_service = document_service
        self.naive_service = naive_service
        self.workload = authenticated_identity

    def read_naive(self, requested_doc: str, correlation_id: str) -> Optional[str]:
        if not self.naive_service:
            return None
        return self.naive_service.get_document(self.workload, requested_doc, correlation_id)

    def read_secure(self, grant: DelegationGrant, requested_doc: str, correlation_id: str) -> Optional[str]:
        return self.doc_service.get_document(
            caller=self.workload, 
            grant=grant, 
            resource_id=requested_doc,
            correlation_id=correlation_id
        )

class ResearchApplication:
    """The public API Boundary"""
    def __init__(self, ds: DelegationService, doc_service: SecureDocumentService, authenticated_agent: AuthenticatedWorkload, naive_service: Optional[NaiveDocumentService] = None, audit_sink: Optional[AuditSink] = None):
        self.ds = ds
        self.agent = ResearchAgent(doc_service, authenticated_agent, naive_service)
        self.audit = audit_sink or AuditSink()

    def answer_naive(self, subject: str, document_id: str, correlation_id: str = "req-1") -> str:
        res = self.agent.read_naive(document_id, correlation_id)
        if res:
            return f"Found document {document_id}: {res}"
        return "Not found."

    def answer_secure(self, principal_context: AuthenticatedPrincipal, document_id: str, correlation_id: str = "req-1") -> ResearchResponse:
        if not ApplicationIdentityProvider.verify(principal_context):
            pid = getattr(principal_context, "principal_id", "unknown")
            self.audit.record(AuditEvent(correlation_id, pid, "research-agent", None, None, "research-agent", "read", document_id, "DENY", "unauthenticated_principal", 0, "blocked"))
            return ResearchResponse("blocked", "Access denied.", correlation_id)
            
        principal = PRINCIPAL_REGISTRY.get(principal_context.principal_id)
        if not principal:
             self.audit.record(AuditEvent(correlation_id, principal_context.principal_id, "research-agent", None, None, "research-agent", "read", document_id, "DENY", "unknown_principal", 0, "blocked"))
             return ResearchResponse("blocked", "Access denied.", correlation_id)
             
        # Issue a tightly scoped grant for this specific operation
        issue_result = self.ds.issue(
            principal_id=principal_context.principal_id,
            delegate_id=self.agent.workload.workload_id,
            audience="document-service",
            requested_operations={"read"},
            requested_resources={document_id}
        )
        
        if not issue_result.grant:
            self.audit.record(AuditEvent(correlation_id, principal_context.principal_id, "research-agent", None, None, "document-service", "read", document_id, "DENY", f"issuance_failed: {issue_result.reason}", 0, "blocked"))
            return ResearchResponse("blocked", "Access denied.", correlation_id)

        res = self.agent.read_secure(issue_result.grant, document_id, correlation_id)
        
        if res:
            return ResearchResponse("answered", f"Found document {document_id}: {res}", correlation_id)
        return ResearchResponse("insufficient_evidence", "I cannot answer this based on authorized available evidence.", correlation_id)

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
    auth_mallory = ApplicationIdentityProvider.for_mallory()
    
    auth_agent = InfrastructureIdentityProvider.for_research_agent()
    auth_doc = InfrastructureIdentityProvider.for_document_service()
    auth_storage = InfrastructureIdentityProvider.for_storage_service()

    storage = StorageService(ds, audit, auth_storage)
    secure_docs = SecureDocumentService(ds, storage, audit, auth_doc)
    naive_docs = NaiveDocumentService(storage, auth_doc)
    
    app = ResearchApplication(ds, secure_docs, auth_agent, naive_docs, audit)
    
    scenarios = []

    def log_scenario(name, result):
        scenarios.append((name, result))
        print(f"[+] {name}\n    -> {result}")

    print("--- 19 Adversarial Scenarios ---\n")

    # 1. Valid delegated read
    res = app.answer_secure(auth_alice, "doc-101", "req-1")
    log_scenario("Valid delegated read", "Allowed" if res.terminal_state == "answered" else "Denied")

    # 2. Unauthorized user resource
    res = app.answer_secure(auth_alice, "doc-secret", "req-2")
    log_scenario("Unauthorized user resource (doc-secret)", "Blocked (issuance_failed: resource_not_owned)" if res.terminal_state == "blocked" else "Leaked")

    # 3. Resource outside grant (use-time check)
    grant_res = ds.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
    res = secure_docs.get_document(auth_agent, grant_res.grant, "doc-102", "req-3")
    log_scenario("Resource outside grant", "Denied (resource_not_delegated)" if not res else "Allowed")

    # 4. Operation outside grant (use-time check)
    decision = ds.verify(grant_res.grant, "research-agent", "document-service", "acme", "delete", "doc-101")
    log_scenario("Operation outside grant (delete)", f"Denied ({decision.reason})" if not decision.allowed else "Allowed")

    # 5. Cross-tenant resource
    res = app.answer_secure(auth_mallory, "doc-101", "req-5")
    log_scenario("Cross-tenant resource (mallory -> acme doc)", "Blocked" if res.terminal_state == "blocked" else "Allowed")

    # 6. Fabricated grant
    fake_grant = DelegationGrant("fake", None, "alice", "document-service", "acme", "storage-service", frozenset({"read"}), frozenset({"doc-101"}), clock(), clock() + timedelta(minutes=60), "hacker")
    res = storage.read_object(auth_doc, fake_grant, "doc-101", "req-6")
    log_scenario("Fabricated grant", "Denied (unknown_delegation)" if not res else "Allowed")

    # 7. Expired grant
    grant_exp = ds.issue("alice", "document-service", "storage-service", {"read"}, {"doc-101"}, ttl_minutes=5)
    class MutableClock:
        def __init__(self, start): self.now = start
        def __call__(self): return self.now
    mc = MutableClock(clock())
    storage.ds._clock_fn = mc
    mc.now += timedelta(minutes=6)
    res = storage.read_object(auth_doc, grant_exp.grant, "doc-101", "req-7")
    storage.ds._clock_fn = clock # reset
    log_scenario("Expired grant", "Denied (delegation_expired)" if not res else "Allowed")

    # 8. Wrong delegate
    grant_wrong = ds.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
    res = secure_docs.get_document(auth_doc, grant_wrong.grant, "doc-101", "req-8") # caller is document-service, but delegate is research-agent
    log_scenario("Wrong delegate", "Denied (delegate_mismatch)" if not res else "Allowed")

    # 9. Wrong audience
    grant_aud = ds.issue("alice", "research-agent", "storage-service", {"read"}, {"doc-101"})
    res = secure_docs.get_document(auth_agent, grant_aud.grant, "doc-101", "req-9") 
    log_scenario("Wrong audience", "Denied (audience_mismatch)" if not res else "Allowed")

    # 10. Workload impersonation (missing identity)
    res = storage.read_object(None, grant_aud.grant, "doc-101", "req-10")
    log_scenario("Workload impersonation (no valid auth)", "Denied (unknown_workload)" if not res else "Allowed")

    # 11. Workload impersonation (forged identity)
    forged_auth = AuthenticatedWorkload("document-service", "acme", "forged-ctx") # Valid ID, but not injected by infrastructure
    # It passes typing, but if we assume the infrastructure validates its own tokens (e.g. at exchange time):
    exch = ds.exchange(grant_wrong.grant, forged_auth, "storage-service", {"read"}, {"doc-101"}, 10)
    # Actually wait, in Python memory this matches the real one. Let's test a mismatched tenant to show consistency checks:
    malformed_auth = AuthenticatedWorkload("document-service", "globex", "forged-ctx")
    exch_malformed = ds.exchange(grant_wrong.grant, malformed_auth, "storage-service", {"read"}, {"doc-101"}, 10)
    log_scenario("Malformed authenticated workload mismatch", f"Denied ({exch_malformed.reason})" if not exch_malformed.grant else "Allowed")

    # 12. Ambient-authority fallback attempt
    ans = app.answer_naive("alice", "doc-secret")
    log_scenario("Ambient-authority fallback (Naive)", "Leaked" if "Acme acquisition plans" in ans else "Blocked")

    # 13. Valid multi-hop exchange
    parent = ds.issue("alice", "research-agent", "document-service", {"read", "comment"}, {"doc-101", "doc-102"})
    child = ds.exchange(parent.grant, auth_doc, "storage-service", {"read"}, {"doc-101"}, 10)
    log_scenario("Valid multi-hop exchange", f"Allowed (Child ID: {child.grant.grant_id})" if child.grant else "Denied")

    # 14. Scope-expansion exchange
    bad_child = ds.exchange(parent.grant, auth_doc, "storage-service", {"read", "delete"}, {"doc-101"}, 10)
    log_scenario("Scope-expansion exchange", f"Denied ({bad_child.reason})" if not bad_child.grant else "Allowed")

    # 15. Child-expiry expansion
    child_exp = ds.exchange(parent.grant, auth_doc, "storage-service", {"read"}, {"doc-101"}, 120)
    log_scenario("Child-expiry expansion", f"Clamped ({child_exp.grant.expires_at == parent.grant.expires_at})" if child_exp.grant and child_exp.grant.expires_at == parent.grant.expires_at else "Failed")

    # 16. Verify Principal Attribution Preservation
    events = [e for e in audit.events if e.correlation_id == "req-1"]
    has_alice_everywhere = all(e.principal_id == "alice" for e in events)
    log_scenario("Principal Attribution Preserved", "Yes" if has_alice_everywhere else "No")

    # 17. Principal impersonation (forged)
    forged_alice = AuthenticatedPrincipal("alice", "forged-ctx")
    res_fake_alice = app.answer_secure(forged_alice, "doc-101", "req-17")
    log_scenario("Principal impersonation (forged auth)", "Denied (unauthenticated_principal)" if res_fake_alice.terminal_state == "blocked" and "unauthenticated_principal" in str(audit.events[-1].reason) else "Allowed")

    # 18. Workload impersonation (missing ID)
    res_missing_wl = storage.read_object(None, grant_aud.grant, "doc-101", "req-18")
    log_scenario("Workload impersonation (missing identity)", "Denied (unauthenticated_workload)" if not res_missing_wl and audit.events[-1].reason == "unauthenticated_workload" else "Allowed")
    
    # 19. Workload impersonation (forged exact metadata)
    forged_doc = AuthenticatedWorkload("document-service", "acme", "forged-ctx")
    res_forged_wl = storage.read_object(forged_doc, grant_aud.grant, "doc-101", "req-19")
    log_scenario("Workload impersonation (forged metadata)", "Denied (unauthenticated_workload)" if not res_forged_wl and audit.events[-1].reason == "unauthenticated_workload" else "Allowed")


    print("\n--- Summary ---")
    print(f"Total Scenarios Run: {len(scenarios)}")

if __name__ == "__main__":
    run_demo()
