import nbformat as nbf
from pathlib import Path

def create_notebook():
    nb = nbf.v4.new_notebook()
    
    nb.cells = [
        nbf.v4.new_markdown_cell(
            "# Intermediate 01: Identity Propagation and Delegated Authority\n\n"
            "In simple systems, knowing *who is calling* is easy. In agentic architectures, a request might hop from the User -> Agent -> Document Service -> Storage Service.\n\n"
            "If the Agent uses its own powerful infrastructure privileges to fetch data, it can be tricked into retrieving documents the original User isn't allowed to see. This is the **Confused Deputy** problem.\n\n"
            "The solution is **Identity Propagation**: securely passing the user's identity and a tightly scoped **Delegation Grant** all the way down the chain. At each hop, the token is **exchanged** for a narrower downstream token, ensuring monotonic attenuation."
        ),
        
        nbf.v4.new_code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "import importlib\n"
            "sys.path.append(str(Path.cwd().parent.parent.parent / 'curriculum' / 'intermediate' / '01-identity-propagation'))\n"
            "lab = importlib.import_module('01_identity_propagation')\n"
            "from datetime import datetime, timezone, timedelta\n\n"
            "class MutableClock:\n"
            "    def __init__(self, start):\n"
            "        self.now = start\n"
            "    def __call__(self):\n"
            "        return self.now\n"
            "    def advance(self, minutes):\n"
            "        self.now += timedelta(minutes=minutes)\n\n"
            "clock = MutableClock(datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc))\n"
            "ds = lab.DelegationService(clock_fn=clock)\n"
            "audit = lab.AuditSink()\n"
            "storage = lab.StorageService(ds, audit)\n"
            "secure_docs = lab.SecureDocumentService(ds, storage, audit)\n"
            "naive_docs = lab.NaiveDocumentService(storage)\n"
            "app = lab.ResearchApplication(ds, secure_docs, naive_docs, audit)\n"
        ),
        
        nbf.v4.new_markdown_cell(
            "## 1. Scenario and Identity Map\n\n"
            "In this lab, we have three users:\n"
            "- **Alice** (Tenant: Acme, Ops: read/comment, Docs: doc-101, doc-102)\n"
            "- **Bob** (Tenant: Acme, Ops: read, Docs: doc-103)\n"
            "- **Mallory** (Tenant: Globex, Ops: read, Docs: doc-globex-01)\n\n"
            "And a highly classified document, `doc-secret`, that no user is allowed to access."
        ),
        
        nbf.v4.new_code_cell(
            "print('--- Principals ---')\n"
            "for pid, p in lab.PRINCIPAL_REGISTRY.items():\n"
            "    print(f\"{pid}: tenant={p.tenant}, ops={list(p.allowed_operations)}, resources={list(p.allowed_resources)}\")\n"
            "print('\\n--- Workloads ---')\n"
            "for wid, w in lab.WORKLOAD_REGISTRY.items():\n"
            "    print(f\"{wid}: tenant={w.tenant}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 2. Principal vs Workload Identity\n"
            "A *Principal* is the human user (Alice). A *Workload Identity* is the software service (research-agent).\n"
            "They are separate. One cannot replace the other.\n\n"
            "## 3. Authentication vs Delegation vs Authorization\n"
            "- **Authentication:** Proving you are who you say you are.\n"
            "- **Delegation:** Granting permission to a workload to act on your behalf.\n"
            "- **Authorization:** Deciding if a specific action is allowed based on the grant."
        ),

        nbf.v4.new_markdown_cell(
            "## 4. Naive Ambient Authority\n"
            "First, let's see how a vulnerable service behaves. The `NaiveDocumentService` trusts the Research Agent's workload identity completely. It uses its *ambient* service-level authority to query storage, ignoring the user."
        ),

        nbf.v4.new_code_cell(
            "my_auth = lab.WorkloadAuthenticator.authenticate('document-service')\n"
            "res = storage.read_object_naive(my_auth, 'doc-secret', 'naive-req')\n"
            "print(f\"Storage Naive Read Result: {res}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 5. Confused Deputy Exploit\n"
            "Because Alice can talk to the Research Agent, and the agent can talk to the Naive Document Service using ambient authority, Alice can trick the agent into retrieving `doc-secret`!"
        ),

        nbf.v4.new_code_cell(
            "ans = app.answer_naive('alice', 'doc-secret')\n"
            "print(f\"Exploit Result: {ans}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 6. Authoritative Principal Resolution\n"
            "In a secure system, a delegation issuer doesn't accept a dictionary or raw object containing scopes. It accepts an identifier, and authoritatively resolves the scopes from a trusted registry (like Entra ID or Okta)."
        ),

        nbf.v4.new_code_cell(
            "principal_id = 'alice'\n"
            "print(f\"Resolving {principal_id} -> {lab.PRINCIPAL_REGISTRY[principal_id]}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 7. Authoritative Workload Authentication\n"
            "Similarly, a string `caller_id = 'document-service'` isn't proof of identity. Authentication requires trusted infrastructure (mTLS, SPIFFE). Our `WorkloadAuthenticator` represents this."
        ),

        nbf.v4.new_code_cell(
            "auth_workload = lab.WorkloadAuthenticator.authenticate('document-service')\n"
            "print(f\"Authenticated Context: {auth_workload}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 8. Delegation Issuance\n"
            "When Alice makes a request, the app issues a tightly scoped **Delegation Grant** binding Alice to the Research Agent."
        ),

        nbf.v4.new_code_cell(
            "grant_101 = ds.issue(\n"
            "    principal_id='alice', \n"
            "    delegate_id='research-agent', \n"
            "    audience='document-service', \n"
            "    requested_operations={'read'}, \n"
            "    requested_resources={'doc-101'}\n"
            ")\n"
            "print(f\"Issued Grant ID: {grant_101.grant_id}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 9. Forged Principal Attack\n"
            "If an attacker tries to pass a forged principal string, the issuer rejects it because it's not in the registry."
        ),

        nbf.v4.new_code_cell(
            "fake_grant = ds.issue('hacker_alice', 'research-agent', 'document-service', {'read'}, {'doc-secret'})\n"
            "print(f\"Forged Principal Grant: {fake_grant}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 10. Forged Grant Attack\n"
            "If an attacker tries to construct a fake `DelegationGrant` object manually and pass it to a service, the service verifies it against the issuer's store. It will fail."
        ),

        nbf.v4.new_code_cell(
            "fake_obj = lab.DelegationGrant('fake-123', None, 'alice', 'document-service', 'acme', 'storage-service', frozenset({'read'}), frozenset({'doc-secret'}), clock(), clock() + timedelta(minutes=60), 'hacker')\n"
            "decision = ds.verify(fake_obj, 'document-service', 'storage-service', 'acme', 'alice', 'read', 'doc-secret')\n"
            "print(f\"Forged Grant Verification: {decision.reason}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 11. Audience Restriction\n"
            "A grant issued for `document-service` cannot be used directly against `storage-service`."
        ),

        nbf.v4.new_code_cell(
            "decision = ds.verify(grant_101, 'research-agent', 'storage-service', 'acme', 'alice', 'read', 'doc-101')\n"
            "print(f\"Audience Mismatch: {decision.reason}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 12. Operation Down-Scoping\n"
            "During issuance, you cannot request operations the principal doesn't have."
        ),

        nbf.v4.new_code_cell(
            "grant = ds.issue('alice', 'research-agent', 'document-service', {'delete'}, {'doc-101'})\n"
            "print(f\"Escalated Operation Grant: {grant}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 13. Resource Down-Scoping\n"
            "Similarly, you cannot request resources the principal doesn't possess."
        ),

        nbf.v4.new_code_cell(
            "grant = ds.issue('alice', 'research-agent', 'document-service', {'read'}, {'doc-secret'})\n"
            "print(f\"Escalated Resource Grant: {grant}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 14. Tenant Binding\n"
            "A user from Acme cannot delegate a workload from Globex, nor access a Globex resource."
        ),

        nbf.v4.new_code_cell(
            "grant = ds.issue('alice', 'evil-agent', 'document-service', {'read'}, {'doc-101'})\n"
            "print(f\"Cross-tenant delegate: {grant}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 15. Expiry\n"
            "Tokens are strictly time-bound."
        ),

        nbf.v4.new_code_cell(
            "grant_exp = ds.issue('alice', 'research-agent', 'document-service', {'read'}, {'doc-101'}, ttl_minutes=5)\n"
            "clock.advance(6)\n"
            "decision = ds.verify(grant_exp, 'research-agent', 'document-service', 'acme', 'alice', 'read', 'doc-101')\n"
            "print(f\"Expired Token: {decision.reason}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 16. No Ambient-Authority Fallback\n"
            "If delegation fails, the service MUST NOT fall back to its ambient privileges. It must fail closed."
        ),

        nbf.v4.new_code_cell(
            "# Reset clock for valid tests\n"
            "clock.now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)\n"
            "res = app.answer_secure('alice', 'doc-secret')\n"
            "print(f\"Secure Fail-Closed Result: {res.terminal_state}\")\n"
            "events = [e for e in audit.events if e.resource_id == 'doc-secret']\n"
            "print(f\"Audit shows DENY: {events[-1].decision} ({events[-1].reason})\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 17. First Secure Delegated Read\n"
            "Now let's see a valid delegated read through the Secure API."
        ),

        nbf.v4.new_code_cell(
            "res = app.answer_secure('alice', 'doc-101', 'req-secure-1')\n"
            "print(f\"Valid Secure Read: {res.answer}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 18. Multi-Hop Token Exchange\n"
            "Notice how the Document Service couldn't use the Research Agent's token for Storage? It had to perform a **Token Exchange**. Let's simulate that manually."
        ),

        nbf.v4.new_code_cell(
            "parent = ds.issue('alice', 'research-agent', 'document-service', {'read', 'comment'}, {'doc-101'}, ttl_minutes=60)\n"
            "doc_auth = lab.WorkloadAuthenticator.authenticate('document-service')\n\n"
            "child = ds.exchange(parent, doc_auth, next_audience='storage-service', requested_operations={'read'}, requested_resources={'doc-101'}, requested_ttl_minutes=10)\n"
            "print(f\"Child Audience: {child.audience}\")\n"
            "print(f\"Child Delegate: {child.delegate_id}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 19. Parent-Child Grant Chain\n"
            "The child grant maintains a cryptographic or deterministic link to the parent grant."
        ),

        nbf.v4.new_code_cell(
            "print(f\"Parent ID: {parent.grant_id}\")\n"
            "print(f\"Child Parent ID: {child.parent_grant_id}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 20. Expiry Attenuation\n"
            "During exchange, a child token cannot outlive its parent. It is clamped to `min(requested_expiry, parent_expiry)`."
        ),

        nbf.v4.new_code_cell(
            "child_long = ds.exchange(parent, doc_auth, 'storage-service', {'read'}, {'doc-101'}, requested_ttl_minutes=120)\n"
            "print(f\"Parent Expiry: {parent.expires_at}\")\n"
            "print(f\"Child Expiry : {child_long.expires_at}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 21. Scope-Expansion Attack\n"
            "If a compromised intermediate service tries to ask for more permissions during exchange, it is denied."
        ),

        nbf.v4.new_code_cell(
            "bad_child = ds.exchange(parent, doc_auth, 'storage-service', {'read', 'delete'}, {'doc-101', 'doc-102'}, requested_ttl_minutes=10)\n"
            "print(f\"Scope Expansion Result: {bad_child}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 22. Workload Impersonation Attack\n"
            "If an attacker tries to call the backend by simply passing a string ID without an AuthenticatedWorkload context, it fails."
        ),

        nbf.v4.new_code_cell(
            "res = storage.read_object(caller=None, grant=child, resource_id='doc-101', correlation_id='req-impersonate')\n"
            "print(f\"Impersonation Result: {res}\")\n"
            "print(f\"Audit: {audit.events[-1].reason}\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 23. Audit/Attribution Trace\n"
            "Let's look at the full audit trace for the successful secure multi-hop request. Notice how identities shift across hops, but Alice is preserved throughout."
        ),

        nbf.v4.new_code_cell(
            "events = [e for e in audit.events if e.correlation_id == 'req-secure-1']\n"
            "for e in events:\n"
            "    print(f\"Hop {e.delegation_depth}: {e.workload_id} -> {e.audience} | {e.operation} {e.resource_id} | {e.lifecycle_state}\")\n"
            "    print(f\"  Principal: {e.principal_id}\")\n"
            "    print(f\"  Grant Chain: {e.delegation_id} (Parent: {e.parent_delegation_id})\\n\")"
        ),

        nbf.v4.new_markdown_cell(
            "## 24. Adversarial Matrix\n"
            "Run `python3 01_identity_propagation.py` in your terminal to see the full demo covering all 14 scenarios.\n\n"
            "## 25. Exercises\n"
            "1. Modify `WorkloadAuthenticator` to deny authentication if `tenant == 'globex'`. How does this affect Mallory?\n"
            "2. Modify the `exchange` method to enforce that the next audience must be in the same tenant.\n\n"
            "## 26. Production Mapping\n"
            "Real token exchange (RFC 8693) involves cryptographic signatures (JWT), Authorization Servers, and complex subject-token verification. This lab models the *semantics*, not the cryptography."
        )
    ]
    
    out_path = Path("curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        nbf.write(nb, f)

if __name__ == "__main__":
    create_notebook()
