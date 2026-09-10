import json
from pathlib import Path

path = Path('curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb')
nb = json.loads(path.read_text())

for cell in nb['cells']:
    if cell['cell_type'] == 'code':
        source = "".join(cell['source'])
        
        # Setup fixes
        if "storage = lab.StorageService(ds, audit)" in source:
            source = source.replace("storage = lab.StorageService(ds, audit)", "auth_agent = lab.InfrastructureIdentityProvider.for_research_agent()\nauth_doc = lab.InfrastructureIdentityProvider.for_document_service()\nauth_storage = lab.InfrastructureIdentityProvider.for_storage_service()\n\nstorage = lab.StorageService(ds, audit, auth_storage)")
            source = source.replace("secure_docs = lab.SecureDocumentService(ds, storage, audit)", "secure_docs = lab.SecureDocumentService(ds, storage, audit, auth_doc)")
            source = source.replace("naive_docs = lab.NaiveDocumentService(storage)", "naive_docs = lab.NaiveDocumentService(storage, auth_doc)")
            source = source.replace("app = lab.ResearchApplication(ds, secure_docs, naive_docs, audit)", "app = lab.ResearchApplication(ds, secure_docs, auth_agent, naive_docs, audit)")
            
        # Auth contexts
        source = source.replace("lab.WorkloadAuthenticator.authenticate('document-service')", "auth_doc")
        source = source.replace("lab.WorkloadAuthenticator.authenticate('storage-service')", "auth_storage")
        
        # ds.issue
        if "grant_101 = ds.issue(" in source:
            source = source.replace("grant_101 = ds.issue(", "grant_101_res = ds.issue(")
            source = source.replace("print(f\"Issued Grant ID: {grant_101.grant_id}\")", "grant_101 = grant_101_res.grant\nprint(f\"Issued Grant ID: {grant_101.grant_id}\")")
            
        if "fake_grant = ds.issue('hacker_alice'" in source:
            source = source.replace("fake_grant = ds.issue", "fake_grant_res = ds.issue")
            source = source.replace("print(f\"Forged Principal Grant: {fake_grant}\")", "print(f\"Forged Principal Grant: {fake_grant_res.reason}\")")
            
        if "grant = ds.issue('alice', 'research-agent', 'document-service', {'delete'}, {'doc-101'})" in source:
            source = source.replace("grant = ds.issue", "grant_res = ds.issue")
            source = source.replace("print(f\"Escalated Operation Grant: {grant}\")", "print(f\"Escalated Operation Grant: {grant_res.reason}\")")

        if "grant = ds.issue('alice', 'research-agent', 'document-service', {'read'}, {'doc-secret'})" in source:
            source = source.replace("grant = ds.issue", "grant_res = ds.issue")
            source = source.replace("print(f\"Escalated Resource Grant: {grant}\")", "print(f\"Escalated Resource Grant: {grant_res.reason}\")")

        if "grant = ds.issue('alice', 'evil-agent'" in source:
            source = source.replace("grant = ds.issue", "grant_res = ds.issue")
            source = source.replace("print(f\"Cross-tenant delegate: {grant}\")", "print(f\"Cross-tenant delegate: {grant_res.reason}\")")

        if "grant_exp = ds.issue('alice', 'research-agent'" in source:
            source = source.replace("grant_exp = ds.issue", "grant_exp_res = ds.issue")
            source = source.replace("decision = ds.verify(grant_exp,", "decision = ds.verify(grant_exp_res.grant,")
            
        if "parent = ds.issue('alice', 'research-agent', 'document-service', {'read', 'comment'}, {'doc-101'}, ttl_minutes=60)" in source:
            source = source.replace("parent = ds.issue", "parent_res = ds.issue")
            source = source.replace("child = ds.exchange(parent, doc_auth", "child_res = ds.exchange(parent_res.grant, doc_auth")
            source = source.replace("child.audience", "child_res.grant.audience")
            source = source.replace("child.delegate_id", "child_res.grant.delegate_id")
            
        if "print(f\"Parent ID: {parent.grant_id}\")" in source:
            source = source.replace("parent.grant_id", "parent_res.grant.grant_id")
            source = source.replace("child.parent_grant_id", "child_res.grant.parent_grant_id")

        if "child_long = ds.exchange(parent, doc_auth" in source:
            source = source.replace("child_long = ds.exchange(parent, doc_auth", "child_long_res = ds.exchange(parent_res.grant, doc_auth")
            source = source.replace("parent.expires_at", "parent_res.grant.expires_at")
            source = source.replace("child_long.expires_at", "child_long_res.grant.expires_at")

        if "bad_child = ds.exchange(parent, doc_auth" in source:
            source = source.replace("bad_child = ds.exchange(parent, doc_auth", "bad_child_res = ds.exchange(parent_res.grant, doc_auth")
            source = source.replace("print(f\"Scope Expansion Result: {bad_child}\")", "print(f\"Scope Expansion Result: {bad_child_res.reason}\")")

        if "res = storage.read_object(caller=None, grant=child," in source:
            source = source.replace("grant=child,", "grant=child_res.grant,")
            
        if "my_auth = auth_doc" in source:
             # Just in case we run it multiple times, we already did replace
             pass
        elif "my_auth = lab.WorkloadAuthenticator.authenticate('document-service')" in source:
             pass # Handled by earlier replace

        cell['source'] = [line + '\n' for line in source.split('\n')]
        # Remove trailing newline from the last item
        if cell['source']:
            cell['source'][-1] = cell['source'][-1].rstrip('\n')

path.write_text(json.dumps(nb, indent=1))
