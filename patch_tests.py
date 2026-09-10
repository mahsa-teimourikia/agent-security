import re
from pathlib import Path

content = Path('tests/test_identity_propagation.py').read_text()

# Fixtures replacements
fixtures_old = """@pytest.fixture
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
    return lab.ResearchApplication(delegation_service, secure_docs, naive_docs, audit)"""

fixtures_new = """@pytest.fixture
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
    return lab.ResearchApplication(delegation_service, secure_docs, auth_agent, naive_docs, audit)"""
content = content.replace(fixtures_old, fixtures_new)

# Test function replacements
content = content.replace("delegation_service.issue", "issue_result = delegation_service.issue").replace("grant = issue_result", "issue_result = delegation_service.issue").replace("grant = delegation_service.issue", "issue_result = delegation_service.issue")
# Actually, let's just use string replace where exact.
content = re.sub(r'grant = delegation_service\.issue\(', r'issue_result = delegation_service.issue(', content)
content = content.replace('assert grant is None', 'assert issue_result.grant is None')
content = content.replace('grant=grant,', 'grant=issue_result.grant,')
content = content.replace('verify(grant,', 'verify(issue_result.grant,')

# Confused Deputy / Impersonation
content = content.replace('def test_expired_delegation(self, delegation_service, storage, clock):', 'def test_expired_delegation(self, delegation_service, storage, clock, auth_storage):')
content = content.replace('auth = lab.WorkloadAuthenticator.authenticate("storage-service")', 'auth = auth_storage')
content = content.replace('"acme", "alice", "read",', '"acme", "read",')

content = content.replace('def test_audience_mismatch(self, delegation_service, storage):', 'def test_audience_mismatch(self, delegation_service, storage, auth_agent):')
content = content.replace('caller = lab.WorkloadAuthenticator.authenticate("research-agent")', 'caller = auth_agent')
content = content.replace('storage.read_object(caller, grant', 'storage.read_object(caller, issue_result.grant')

content = content.replace('def test_delegate_mismatch(self, delegation_service, storage):', 'def test_delegate_mismatch(self, delegation_service, storage, auth_doc):')
content = content.replace('caller = lab.WorkloadAuthenticator.authenticate("document-service") # Wrong caller', 'caller = auth_doc # Wrong caller')

content = content.replace('def test_tenant_mismatch(self, delegation_service):', 'def test_tenant_mismatch(self, delegation_service):')
content = content.replace('"globex", "alice", "read", "doc-101"', '"globex", "read", "doc-101"')

content = content.replace('def test_fabricated_grant_rejected(self, storage, clock):', 'def test_fabricated_grant_rejected(self, storage, clock, auth_storage):')
content = content.replace('caller = lab.WorkloadAuthenticator.authenticate("storage-service")', 'caller = auth_storage')

content = content.replace('parent = delegation_service.issue(', 'parent = delegation_service.issue(')
# exchange tests
exchange_tests_sub = [
    ('def test_exchange_valid(self, delegation_service):', 'def test_exchange_valid(self, delegation_service, auth_doc):'),
    ('def test_exchange_operation_expansion_denied(self, delegation_service):', 'def test_exchange_operation_expansion_denied(self, delegation_service, auth_doc):'),
    ('def test_exchange_resource_expansion_denied(self, delegation_service):', 'def test_exchange_resource_expansion_denied(self, delegation_service, auth_doc):'),
    ('def test_exchange_expiry_never_exceeds_parent(self, delegation_service):', 'def test_exchange_expiry_never_exceeds_parent(self, delegation_service, auth_doc):'),
    ('def test_exchange_tenant_preserved(self, delegation_service):', 'def test_exchange_tenant_preserved(self, delegation_service, auth_doc):')
]
for old, new in exchange_tests_sub:
    content = content.replace(old, new)

content = content.replace('doc_svc = lab.WorkloadAuthenticator.authenticate("document-service")', 'doc_svc = auth_doc')
content = content.replace('delegation_service.exchange(parent,', 'delegation_service.exchange(parent.grant,')
content = content.replace('assert child is None', 'assert child.grant is None')
content = content.replace('assert child is not None', 'assert child.grant is not None')
content = content.replace('child.parent_grant_id', 'child.grant.parent_grant_id')
content = content.replace('parent.grant_id', 'parent.grant.grant_id')
content = content.replace('child.principal_id', 'child.grant.principal_id')
content = content.replace('child.audience', 'child.grant.audience')
content = content.replace('child.allowed_operations', 'child.grant.allowed_operations')
content = content.replace('child.allowed_resources', 'child.grant.allowed_resources')
content = content.replace('child.expires_at == parent.expires_at', 'child.grant.expires_at == parent.grant.expires_at')

content = re.sub(r'parent = delegation_service\.issue\(', r'parent = delegation_service.issue(', content)

# Remove principal_mismatch completely
principal_mismatch_code = """    def test_principal_mismatch(self, delegation_service, storage):
        issue_result = delegation_service.issue("alice", "storage-service", "storage-service", {"read"}, {"doc-101"})
        # Storage internal verification asks for "bob" instead of "alice"
        caller = lab.WorkloadAuthenticator.authenticate("storage-service")
        decision = delegation_service.verify(issue_result.grant, "storage-service", "storage-service", "acme", "bob", "read", "doc-101")
        assert not decision.allowed
        assert decision.reason == "principal_mismatch"
        """
content = content.replace(principal_mismatch_code, '')


# Re-save
Path('tests/test_identity_propagation.py').write_text(content)
