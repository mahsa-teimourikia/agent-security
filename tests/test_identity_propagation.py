import pytest
import sys
import importlib
from pathlib import Path
from datetime import datetime, timezone, timedelta

mod_path = Path(__file__).parent.parent / "curriculum" / "intermediate" / "01-identity-propagation"
sys.path.insert(0, str(mod_path.resolve()))
lab = importlib.import_module("01_identity_propagation")

@pytest.fixture
def clock():
    return lambda: datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)

@pytest.fixture
def delegation_service(clock):
    return lab.DelegationService(clock_fn=clock)

@pytest.fixture
def audit():
    return lab.AuditSink()

@pytest.fixture
def auth_storage():
    return lab.InfrastructureIdentityProvider.for_storage_service()

@pytest.fixture
def auth_doc():
    return lab.InfrastructureIdentityProvider.for_document_service()

@pytest.fixture
def auth_agent():
    return lab.InfrastructureIdentityProvider.for_research_agent()

@pytest.fixture
def storage(delegation_service, audit, auth_storage):
    return lab.StorageService(delegation_service, audit, auth_storage)

@pytest.fixture
def secure_docs(delegation_service, storage, audit, auth_doc):
    return lab.SecureDocumentService(delegation_service, storage, audit, auth_doc)

@pytest.fixture
def naive_docs(storage, auth_doc):
    return lab.NaiveDocumentService(storage, auth_doc)

@pytest.fixture
def app(delegation_service, secure_docs, naive_docs, audit, auth_agent):
    return lab.ResearchApplication(delegation_service, secure_docs, auth_agent, naive_docs, audit)

class TestIdentityPropagation:

    # --- Identity & Execution ---
    def test_known_principal_allowed(self, app):
        resp = app.answer_secure("alice", "doc-101")
        assert resp.terminal_state == "answered"
        assert "Found document" in resp.answer

    def test_unknown_principal_rejected(self, app):
        resp = app.answer_secure("unknown_user", "doc-101")
        assert resp.terminal_state == "blocked"
        assert app.audit.events[-1].reason == "unknown_principal"

    def test_known_principal_unauthorized_resource(self, app):
        resp = app.answer_secure("alice", "doc-secret")
        assert resp.terminal_state == "blocked"
        assert "issuance_failed: " in app.audit.events[-1].reason

    def test_cross_tenant_rejected(self, app):
        # Mallory is Globex, tries to access Acme doc
        resp = app.answer_secure("mallory", "doc-101")
        assert resp.terminal_state == "blocked"
        assert "issuance_failed: " in app.audit.events[-1].reason

    # --- Trust Boundaries ---
    def test_forged_principal_cannot_issue(self, delegation_service):
        # We try to use a fake Principal object, but DelegationService.issue only takes strings now
        # and looks it up in the authoritative PRINCIPAL_REGISTRY. If we try to pass a non-existent
        # string, it fails.
        issue_result = delegation_service.issue = delegation_service.issue(
            principal_id="fake_alice", 
            delegate_id="research-agent", 
            audience="document-service", 
            requested_operations={"read"}, 
            requested_resources={"doc-secret"}
        )
        assert issue_result.grant is None

    def test_unknown_workload_cannot_issue(self, delegation_service):
        issue_result = delegation_service.issue = delegation_service.issue(
            principal_id="alice", 
            delegate_id="fake-agent", 
            audience="document-service", 
            requested_operations={"read"}, 
            requested_resources={"doc-101"}
        )
        assert issue_result.grant is None

    def test_unknown_audience_cannot_issue(self, delegation_service):
        issue_result = delegation_service.issue = delegation_service.issue(
            principal_id="alice", 
            delegate_id="research-agent", 
            audience="fake-service", 
            requested_operations={"read"}, 
            requested_resources={"doc-101"}
        )
        assert issue_result.grant is None

    def test_workload_impersonation(self, storage, delegation_service):
        # An attacker knows "document-service" is a valid workload ID, 
        # but they cannot create a valid AuthenticatedWorkload via the WorkloadAuthenticator 
        # unless they truly are the document-service (simulated here).
        # Even if they create a raw object (which is possible in Python but violates the API contract),
        # the storage service validates against the grant. But let's test if we pass None.
        issue_result = delegation_service.issue = delegation_service.issue("alice", "research-agent", "storage-service", {"read"}, {"doc-101"})
        res = storage.read_object(caller=None, grant=issue_result.grant, resource_id="doc-101", correlation_id="req-steal")
        assert res is None
        assert storage.audit.events[-1].reason == "unknown_workload"
        assert storage.audit.events[-1].lifecycle_state == "blocked"

    # --- Confused Deputy ---
    def test_confused_deputy_naive(self, app):
        ans = app.answer_naive("alice", "doc-secret")
        assert "Acme acquisition plans" in ans

    def test_confused_deputy_secure(self, app):
        resp = app.answer_secure("alice", "doc-secret")
        assert resp.terminal_state == "blocked"
        assert "Acme acquisition plans" not in str(resp.answer)
        
    def test_secure_no_fallback_to_ambient_authority(self, app):
        # If delegation fails, the service MUST NOT fall back to reading ambiently.
        resp = app.answer_secure("alice", "doc-secret")
        assert resp.terminal_state == "blocked"
        
        # We can see that Document Service attempted to read, failed delegation, 
        # and stopped, without falling back to ambient authority to fetch doc-secret.
        events = [e for e in app.audit.events if e.resource_id == "doc-secret"]
        assert all(e.decision == "DENY" for e in events)

    # --- Delegation Issuance & Constraints ---
    def test_invalid_ttl_rejected(self, delegation_service):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"}, ttl_minutes=-5)
        assert issue_result.grant is None

    def test_delegation_cannot_escalate_operations(self, delegation_service):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "research-agent", "document-service", {"delete"}, {"doc-101"})
        assert issue_result.grant is None

    def test_delegation_cannot_escalate_resources(self, delegation_service):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "research-agent", "document-service", {"read"}, {"doc-secret"})
        assert issue_result.grant is None

    def test_cross_tenant_issuance(self, delegation_service):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "evil-agent", "document-service", {"read"}, {"doc-101"}) # alice (acme), evil (globex)
        assert issue_result.grant is None

    # --- Verification ---
    def test_expired_delegation(self, delegation_service, storage, clock, auth_storage):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "storage-service", "storage-service", {"read"}, {"doc-101"}, ttl_minutes=60)
        
        class MutableClock:
            def __init__(self, start):
                self.now = start
            def __call__(self):
                return self.now
            def advance(self, minutes):
                self.now += timedelta(minutes=minutes)
                
        mc = MutableClock(clock())
        storage.ds._clock_fn = mc
        
        # Valid at issuance
        mc.advance(59)
        auth = auth_storage
        assert storage.ds.verify(issue_result.grant, "storage-service", "storage-service", "acme", "read", "doc-101").allowed
        
        # Expired at boundary
        mc.advance(1) # exactly 60
        assert not storage.ds.verify(issue_result.grant, "storage-service", "storage-service", "acme", "read", "doc-101").allowed

    def test_audience_mismatch(self, delegation_service, storage, auth_agent):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
        caller = auth_agent
        res = storage.read_object(caller, issue_result.grant, "doc-101", "req-1")
        assert res is None
        assert storage.audit.events[-1].reason == "audience_mismatch"

    def test_delegate_mismatch(self, delegation_service, storage, auth_doc):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "research-agent", "storage-service", {"read"}, {"doc-101"})
        caller = auth_doc # Wrong caller
        res = storage.read_object(caller, issue_result.grant, "doc-101", "req-1")
        assert res is None
        assert storage.audit.events[-1].reason == "delegate_mismatch"
        
    def test_tenant_mismatch(self, delegation_service):
        issue_result = delegation_service.issue = delegation_service.issue("alice", "document-service", "document-service", {"read"}, {"doc-101"})
        decision = delegation_service.verify(issue_result.grant, "document-service", "document-service", "globex", "read", "doc-101")
        assert not decision.allowed
        assert decision.reason == "tenant_mismatch"

    def test_fabricated_grant_rejected(self, storage, clock, auth_storage):
        fake_grant = lab.DelegationGrant(
            grant_id="fake-1",
            parent_grant_id=None,
            principal_id="alice",
            delegate_id="storage-service",
            tenant="acme",
            audience="storage-service",
            allowed_operations=frozenset({"read"}),
            allowed_resources=frozenset({"doc-101"}),
            issued_at=clock(),
            expires_at=clock() + timedelta(minutes=60),
            issuer="hacker"
        )
        caller = auth_storage
        res = storage.read_object(caller, fake_grant, "doc-101", "req-1")
        assert res is None
        assert storage.audit.events[-1].reason == "unknown_delegation"

    # --- Exchange (Token Down-Scoping) ---
    def test_exchange_valid(self, delegation_service, auth_doc):
        parent = issue_result = delegation_service.issue("alice", "research-agent", "document-service", {"read", "comment"}, {"doc-101", "doc-102"})
        doc_svc = auth_doc
        child = delegation_service.exchange(parent.grant, doc_svc, "storage-service", {"read"}, {"doc-101"}, 5)
        
        assert child.grant is not None
        assert child.grant.parent_grant_id == parent.grant.grant_id
        assert child.grant.principal_id == "alice"
        assert child.grant.audience == "storage-service"
        assert child.grant.allowed_operations == frozenset({"read"})
        assert child.grant.allowed_resources == frozenset({"doc-101"})

    def test_exchange_operation_expansion_denied(self, delegation_service, auth_doc):
        parent = issue_result = delegation_service.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
        doc_svc = auth_doc
        child = delegation_service.exchange(parent.grant, doc_svc, "storage-service", {"read", "comment"}, {"doc-101"}, 5)
        assert child.grant is None
        
    def test_exchange_resource_expansion_denied(self, delegation_service, auth_doc):
        parent = issue_result = delegation_service.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
        doc_svc = auth_doc
        child = delegation_service.exchange(parent.grant, doc_svc, "storage-service", {"read"}, {"doc-101", "doc-102"}, 5)
        assert child.grant is None

    def test_exchange_expiry_never_exceeds_parent(self, delegation_service, auth_doc):
        parent = issue_result = delegation_service.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"}, ttl_minutes=10)
        doc_svc = auth_doc
        
        # Request 60 minutes
        child = delegation_service.exchange(parent.grant, doc_svc, "storage-service", {"read"}, {"doc-101"}, 60)
        
        assert child.grant.expires_at == parent.grant.expires_at # Clamped to parent expiry
        
    def test_exchange_tenant_preserved(self, delegation_service, auth_doc):
        parent = issue_result = delegation_service.issue("alice", "research-agent", "document-service", {"read"}, {"doc-101"})
        doc_svc = auth_doc
        child = delegation_service.exchange(parent.grant, doc_svc, "evil-agent", {"read"}, {"doc-101"}, 5) # evil-agent is globex
        assert child.grant is None # Cross-tenant next audience denied

    # --- Multi-Hop Downscoping & Audit ---
    def test_multi_hop_downscoping(self, app):
        resp = app.answer_secure("alice", "doc-101", "req-hop")
        
        # Verify Audit chain
        events = [e for e in app.audit.events if e.correlation_id == "req-hop"]
        assert len(events) == 2
        
        hop_1 = events[0]
        assert hop_1.delegation_depth == 1
        assert hop_1.workload_id == "research-agent"
        assert hop_1.audience == "document-service"
        assert hop_1.decision == "ALLOW"
        assert hop_1.lifecycle_state == "forwarded"
        
        hop_2 = events[1]
        assert hop_2.delegation_depth == 2
        assert hop_2.workload_id == "document-service"
        assert hop_2.audience == "storage-service"
        assert hop_2.decision == "ALLOW"
        assert hop_2.lifecycle_state == "accessed"
        
        # The grant IDs should be different because of token exchange
        assert hop_1.delegation_id != hop_2.delegation_id
        assert hop_2.parent_delegation_id == hop_1.delegation_id

    def test_audit_preserves_identities(self, app):
        app.answer_secure("alice", "doc-101", "req-audit")
        event = app.audit.events[-1]
        
        assert event.correlation_id == "req-audit"
        assert event.principal_id == "alice"
        assert event.workload_id == "document-service" # deepest hop workload caller
        assert event.audience == "storage-service"
        assert event.operation == "read"
        assert event.resource_id == "doc-101"
        assert event.decision == "ALLOW"
        # Never log raw tokens!
        assert not hasattr(event, "raw_token")
