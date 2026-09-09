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
from typing import Optional, List, Set, Dict, Tuple, FrozenSet

# ------------------------------------------------------------------------
# 1. Identity & Resource Models
# ------------------------------------------------------------------------

@dataclass(frozen=True)
class Principal:
    """The authenticated end user (the human)."""
    principal_id: str
    tenant: str
    allowed_operations: FrozenSet[str]
    allowed_resources: FrozenSet[str]

@dataclass(frozen=True)
class WorkloadIdentity:
    """The authenticated service or agent (the software)."""
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

@dataclass
class AuditEvent:
    correlation_id: str
    principal_id: Optional[str]
    workload_id: str
    delegation_id: Optional[str]
    audience: str
    operation: str
    resource_id: str
    decision: str
    reason: str
    delegation_depth: int
    terminal_state: str

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
        principal: Principal, 
        delegate: WorkloadIdentity, 
        audience: str, 
        requested_operations: Set[str], 
        requested_resources: Set[str],
        ttl_minutes: int = 60
    ) -> Optional[DelegationGrant]:
        """Issue a grant, enforcing that delegated authority cannot exceed principal authority."""
        
        # 1. Enforce monotonic down-scoping during issuance
        if not requested_operations.issubset(principal.allowed_operations):
            return None # Cannot delegate an operation the principal doesn't have
            
        if not requested_resources.issubset(principal.allowed_resources):
            return None # Cannot delegate a resource the principal doesn't have
            
        # 2. Enforce tenant boundary
        if principal.tenant != delegate.tenant:
            return None # Cross-tenant delegation denied
            
        now = self._clock_fn()
        grant_id = f"grant-{self._counter}"
        self._counter += 1
        
        grant = DelegationGrant(
            grant_id=grant_id,
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
        return grant
        
    def verify(
        self, 
        grant: DelegationGrant, 
        expected_delegate_id: str, 
        expected_audience: str, 
        expected_tenant: str,
        operation: str,
        resource_id: str
    ) -> AuthorizationDecision:
        """Verify the authenticity and validity of the grant."""
        
        now = self._clock_fn()
        
        # 1. Check authenticity
        if grant.grant_id not in self._store or self._store[grant.grant_id] != grant:
            return AuthorizationDecision(False, "unknown_delegation")
            
        # 2. Check Expiry
        if now > grant.expires_at:
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
            
        # 6. Enforce Operation Scope
        if operation not in grant.allowed_operations:
            return AuthorizationDecision(False, "operation_not_delegated")
            
        # 7. Enforce Resource Scope
        if resource_id not in grant.allowed_resources:
            return AuthorizationDecision(False, "resource_not_delegated")
            
        return AuthorizationDecision(True, "allow")

# ------------------------------------------------------------------------
# 5. Storage Service (Deepest Hop)
# ------------------------------------------------------------------------

class StorageService:
    """The lowest level service. It requires an exact valid token to release data."""
    def __init__(self, delegation_service: DelegationService, audit_sink: AuditSink):
        self.ds = delegation_service
        self.audit = audit_sink
        self.workload = WORKLOAD_REGISTRY["storage-service"]

    def read_object(self, caller_id: str, grant: Optional[DelegationGrant], resource_id: str, correlation_id: str, depth: int = 2) -> Optional[str]:
        # 1. Resolve authenticated caller (simulate mutual TLS/service auth)
        caller = WORKLOAD_REGISTRY.get(caller_id)
        if not caller:
            self._audit(correlation_id, None, caller_id, grant, "read", resource_id, "DENY", "unknown_workload", depth)
            return None
            
        # 2. Check resource existence and ownership
        resource = RESOURCE_REGISTRY.get(resource_id)
        if not resource:
            self._audit(correlation_id, None, caller_id, grant, "read", resource_id, "DENY", "unknown_resource", depth)
            return None

        # 3. Authorize via Delegation
        if not grant:
             self._audit(correlation_id, None, caller_id, None, "read", resource_id, "DENY", "missing_delegation", depth)
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
            self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "DENY", decision.reason, depth)
            return None
            
        # Success
        self._audit(correlation_id, grant.principal_id, caller.workload_id, grant, "read", resource_id, "ALLOW", "success", depth)
        return DOCUMENT_STORE.get(resource_id)

    def _audit(self, cid, pid, wid, grant, op, res, decision, reason, depth):
        self.audit.record(AuditEvent(cid, pid, wid, grant.grant_id if grant else None, self.workload.workload_id, op, res, decision, reason, depth, "blocked" if decision == "DENY" else "answered"))


# ------------------------------------------------------------------------
# 6. Document Services (The Deputies)
# ------------------------------------------------------------------------

class NaiveDocumentService:
    """
    VULNERABLE: Confused Deputy.
    This service accepts the agent's workload identity as sufficient authorization,
    ignoring the user entirely. It uses ambient authority to query the backend.
    """
    def __init__(self, storage: StorageService):
        self.storage = storage

    def get_document(self, agent_id: str, resource_id: str, correlation_id: str) -> Optional[str]:
        # Agent claims to be authorized, and it is a trusted internal service!
        if agent_id == "research-agent":
            # The naive service completely bypasses delegation and just forces the storage service
            # (Assume in naive mode storage doesn't require a grant, or the document service
            # mints a master grant for itself. We'll simulate by pulling directly from store).
            return DOCUMENT_STORE.get(resource_id)
        return None

class SecureDocumentService:
    """
    SECURE: Identity Propagation.
    This service verifies the incoming grant, then explicitly down-scopes and 
    exchanges the grant for a new one destined for the Storage Service.
    """
    def __init__(self, delegation_service: DelegationService, storage: StorageService, audit_sink: AuditSink):
        self.ds = delegation_service
        self.storage = storage
        self.audit = audit_sink
        self.workload = WORKLOAD_REGISTRY["document-service"]

    def get_document(self, caller_id: str, grant: Optional[DelegationGrant], resource_id: str, correlation_id: str, depth: int = 1) -> Optional[str]:
        # 1. Resolve Workload
        caller = WORKLOAD_REGISTRY.get(caller_id)
        if not caller:
            self._audit(correlation_id, None, caller_id, grant, "read", resource_id, "DENY", "unknown_workload", depth)
            return None

        # 2. Resource tenant resolution
        resource = RESOURCE_REGISTRY.get(resource_id)
        if not resource:
             self._audit(correlation_id, None, caller_id, grant, "read", resource_id, "DENY", "unknown_resource", depth)
             return None

        if not grant:
            self._audit(correlation_id, None, caller_id, None, "read", resource_id, "DENY", "missing_delegation", depth)
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
            self._audit(correlation_id, grant.principal_id, caller_id, grant, "read", resource_id, "DENY", decision.reason, depth)
            return None

        self._audit(correlation_id, grant.principal_id, caller_id, grant, "read", resource_id, "ALLOW", "propagating_downstream", depth)

        # 4. Multi-hop Down-scoping (Token Exchange)
        # The document service creates a smaller scope token specifically for the storage service.
        principal_pseudo = Principal(grant.principal_id, grant.tenant, grant.allowed_operations, grant.allowed_resources)
        downstream_grant = self.ds.issue(
            principal=principal_pseudo,
            delegate=self.workload, # Now the DocumentService is the delegate
            audience="storage-service",
            requested_operations={"read"},
            requested_resources={resource_id},
            ttl_minutes=5 # Tighter expiry for downstream
        )
        
        if not downstream_grant:
             # Should not happen unless requested out-of-bounds
             return None

        # 5. Call downstream StorageService with the new Down-scoped Grant
        return self.storage.read_object(
            caller_id=self.workload.workload_id,
            grant=downstream_grant,
            resource_id=resource_id,
            correlation_id=correlation_id,
            depth=depth + 1
        )

    def _audit(self, cid, pid, wid, grant, op, res, decision, reason, depth):
        self.audit.record(AuditEvent(cid, pid, wid, grant.grant_id if grant else None, self.workload.workload_id, op, res, decision, reason, depth, "blocked" if decision == "DENY" else "answered"))


# ------------------------------------------------------------------------
# 7. Agent & Application
# ------------------------------------------------------------------------

class ResearchAgent:
    def __init__(self, document_service: SecureDocumentService, naive_service: Optional[NaiveDocumentService] = None):
        self.doc_service = document_service
        self.naive_service = naive_service
        self.workload = WORKLOAD_REGISTRY["research-agent"]

    def read_naive(self, requested_doc: str, correlation_id: str) -> Optional[str]:
        # Agent has broad infra privilege and uses it blindly
        if not self.naive_service:
            return None
        return self.naive_service.get_document(self.workload.workload_id, requested_doc, correlation_id)

    def read_secure(self, grant: DelegationGrant, requested_doc: str, correlation_id: str) -> Optional[str]:
        return self.doc_service.get_document(
            caller_id=self.workload.workload_id, 
            grant=grant, 
            resource_id=requested_doc,
            correlation_id=correlation_id
        )

class ResearchApplication:
    """The public API Boundary"""
    def __init__(self, ds: DelegationService, doc_service: SecureDocumentService, naive_service: Optional[NaiveDocumentService] = None, audit_sink: Optional[AuditSink] = None):
        self.ds = ds
        self.agent = ResearchAgent(doc_service, naive_service)
        self.audit = audit_sink or AuditSink()

    def answer_naive(self, subject: str, document_id: str, correlation_id: str = "req-1") -> str:
        # Resolves user, but ignores them and uses ambient agent authority
        res = self.agent.read_naive(document_id, correlation_id)
        if res:
            return f"Found document {document_id}: {res}"
        return "Not found."

    def answer_secure(self, subject: str, document_id: str, correlation_id: str = "req-1") -> ResearchResponse:
        principal = PRINCIPAL_REGISTRY.get(subject)
        if not principal:
             self.audit.record(AuditEvent(correlation_id, subject, "research-agent", None, "research-agent", "read", document_id, "DENY", "unknown_principal", 0, "blocked"))
             return ResearchResponse("blocked", "Access denied.", correlation_id)
             
        # Issue a tightly scoped grant for this specific operation
        grant = self.ds.issue(
            principal=principal,
            delegate=self.agent.workload,
            audience="document-service",
            requested_operations={"read"},
            requested_resources={document_id}
        )
        
        if not grant:
            self.audit.record(AuditEvent(correlation_id, subject, "research-agent", None, "document-service", "read", document_id, "DENY", "delegation_issuance_failed", 0, "blocked"))
            return ResearchResponse("blocked", "Access denied.", correlation_id)

        res = self.agent.read_secure(grant, document_id, correlation_id)
        
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
    
    storage = StorageService(ds, audit)
    secure_docs = SecureDocumentService(ds, storage, audit)
    naive_docs = NaiveDocumentService(storage)
    
    app = ResearchApplication(ds, secure_docs, naive_docs, audit)
    
    print("[!] 1. Naive Confused Deputy Attack")
    print("Alice uses the agent's broad ambient authority to read a secret document she does not own.")
    ans = app.answer_naive("alice", "doc-secret")
    print(f"Result: {ans}\n")
    
    print("[!] 2. Secure Identity Propagation")
    print("Alice attempts to read doc-101 (Allowed) and doc-secret (Denied).")
    r1 = app.answer_secure("alice", "doc-101", "req-101")
    r2 = app.answer_secure("alice", "doc-secret", "req-102")
    print(f"Doc-101 Result: {r1.answer}")
    print(f"Doc-Secret Result: {r2.answer}\n")
    
    print("[!] 3. Delegation Audit Trail for doc-101")
    events = [e for e in audit.events if e.correlation_id == "req-101"]
    for e in events:
        print(f"Hop {e.delegation_depth}: {e.workload_id} -> {e.audience} | {e.operation} {e.resource_id} | {e.decision} ({e.reason})")

if __name__ == "__main__":
    run_demo()
