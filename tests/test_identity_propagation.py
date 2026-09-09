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
def storage(delegation_service, audit):
    return lab.StorageService(delegation_service, audit)

@pytest.fixture
def secure_docs(delegation_service, storage, audit):
    return lab.SecureDocumentService(delegation_service, storage, audit)

@pytest.fixture
def naive_docs(storage):
    return lab.NaiveDocumentService(storage)

@pytest.fixture
def app(delegation_service, secure_docs, naive_docs, audit):
    return lab.ResearchApplication(delegation_service, secure_docs, naive_docs, audit)

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
        assert app.audit.events[-1].reason == "delegation_issuance_failed"

    def test_cross_tenant_rejected(self, app):
        # Mallory is Globex, tries to access Acme doc
        resp = app.answer_secure("mallory", "doc-101")
        assert resp.terminal_state == "blocked"
        assert app.audit.events[-1].reason == "delegation_issuance_failed"

    # --- Confused Deputy ---
    def test_confused_deputy_naive(self, app):
        # Alice requests doc-secret via naive method.
        # It succeeds because naive ignores Alice's delegation limits.
        ans = app.answer_naive("alice", "doc-secret")
        assert "Acme acquisition plans" in ans

    def test_confused_deputy_secure(self, app):
        # Alice requests doc-secret via secure method.
        # Fails issuance because Alice doesn't have doc-secret.
        resp = app.answer_secure("alice", "doc-secret")
        assert resp.terminal_state == "blocked"
        assert "Acme acquisition plans" not in str(resp.answer)

    # --- Delegation Issuance ---
    def test_delegation_cannot_escalate_operations(self, delegation_service):
        alice = lab.PRINCIPAL_REGISTRY["alice"] # can 'read', 'comment'
        agent = lab.WORKLOAD_REGISTRY["research-agent"]
        
        # Requesting 'delete' should fail
        grant = delegation_service.issue(alice, agent, "doc-service", {"delete"}, {"doc-101"})
        assert grant is None

    def test_delegation_cannot_escalate_resources(self, delegation_service):
        alice = lab.PRINCIPAL_REGISTRY["alice"] # can 'doc-101', 'doc-102'
        agent = lab.WORKLOAD_REGISTRY["research-agent"]
        
        # Requesting 'doc-secret' should fail
        grant = delegation_service.issue(alice, agent, "doc-service", {"read"}, {"doc-secret"})
        assert grant is None

    # --- Verification & Down-scoping ---
    def test_expired_delegation(self, delegation_service, storage):
        alice = lab.PRINCIPAL_REGISTRY["alice"]
        agent = lab.WORKLOAD_REGISTRY["storage-service"]
        
        grant = delegation_service.issue(alice, agent, "storage-service", {"read"}, {"doc-101"}, ttl_minutes=-10)
        
        # Directly call storage with expired grant
        res = storage.read_object("storage-service", grant, "doc-101", "req-1")
        assert res is None
        assert storage.audit.events[-1].reason == "delegation_expired"

    def test_audience_mismatch(self, delegation_service, storage):
        alice = lab.PRINCIPAL_REGISTRY["alice"]
        agent = lab.WORKLOAD_REGISTRY["storage-service"]
        
        # Grant for 'email-service'
        grant = delegation_service.issue(alice, agent, "email-service", {"read"}, {"doc-101"})
        
        res = storage.read_object("storage-service", grant, "doc-101", "req-1")
        assert res is None
        assert storage.audit.events[-1].reason == "audience_mismatch"

    def test_delegate_mismatch(self, delegation_service, storage):
        alice = lab.PRINCIPAL_REGISTRY["alice"]
        agent = lab.WORKLOAD_REGISTRY["research-agent"] # Issued to agent
        
        grant = delegation_service.issue(alice, agent, "storage-service", {"read"}, {"doc-101"})
        
        # storage-service tries to use it itself (wrong delegate)
        res = storage.read_object("storage-service", grant, "doc-101", "req-1")
        assert res is None
        assert storage.audit.events[-1].reason == "delegate_mismatch"

    def test_fabricated_grant_rejected(self, storage, clock):
        # Create a grant without issuing it through DelegationService
        fake_grant = lab.DelegationGrant(
            grant_id="fake-1",
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
        
        res = storage.read_object("storage-service", fake_grant, "doc-101", "req-1")
        assert res is None
        assert storage.audit.events[-1].reason == "unknown_delegation"

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
        
        hop_2 = events[1]
        assert hop_2.delegation_depth == 2
        assert hop_2.workload_id == "document-service"
        assert hop_2.audience == "storage-service"
        assert hop_2.decision == "ALLOW"
        
        # The grant IDs should be different because of token exchange
        assert hop_1.delegation_id != hop_2.delegation_id

    # --- Audit Trail ---
    def test_audit_preserves_identities(self, app):
        app.answer_secure("alice", "doc-101", "req-audit")
        event = app.audit.events[-1]
        
        assert event.correlation_id == "req-audit"
        assert event.principal_id == "alice"
        assert event.workload_id == "document-service"
        assert event.audience == "storage-service"
        assert event.operation == "read"
        assert event.resource_id == "doc-101"
        assert event.decision == "ALLOW"
