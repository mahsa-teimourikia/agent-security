import nbformat as nbf
from pathlib import Path


def create_notebook():
    nb = nbf.v4.new_notebook()

    nb.cells = [
        nbf.v4.new_markdown_cell(
            "# Intermediate 01: Identity Propagation and Delegated Authority\n\n"
            "In simple systems, knowing *who is calling* is easy. In agentic architectures, a request might hop from the User -> Agent -> Document Service -> Storage Service.\n\n"
            "If the Agent uses its own powerful infrastructure privileges to fetch data, it can be tricked into retrieving documents the original User isn't allowed to see. This is the **Confused Deputy** problem.\n\n"
            "The solution is **Identity Propagation**: securely passing the user's identity and a tightly scoped **Delegation Grant** all the way down the chain. At each hop, the token is **exchanged** for a narrower downstream token, ensuring monotonic attenuation.\n\n"
            "![Identity propagation trust boundaries](architecture.svg)"
        ),
        nbf.v4.new_code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "import importlib\n"
            "course_rel = Path('curriculum/intermediate/01-identity-propagation')\n"
            "repo_root = next((root for root in (Path.cwd(), *Path.cwd().parents) if (root / course_rel).is_dir()), None)\n"
            "if repo_root is None:\n"
            "    raise RuntimeError('Run this notebook from the repository or course directory')\n"
            "course_dir = repo_root / course_rel\n"
            "sys.path.insert(0, str(course_dir))\n"
            "lab = importlib.import_module('01_identity_propagation')\n"
            "sdk = importlib.import_module('01_identity_propagation_sdk')\n"
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
            "auth_alice = lab.ApplicationIdentityProvider.for_alice()\n"
            "auth_bob = lab.ApplicationIdentityProvider.for_bob()\n"
            "auth_mallory = lab.ApplicationIdentityProvider.for_mallory()\n"
            "auth_agent = lab.InfrastructureIdentityProvider.for_research_agent()\n"
            "auth_doc = lab.InfrastructureIdentityProvider.for_document_service()\n"
            "auth_storage = lab.InfrastructureIdentityProvider.for_storage_service()\n"
            "auth_evil = lab.InfrastructureIdentityProvider.for_evil_agent()\n"
            "auth_job = lab.ServiceJobIdentityProvider.for_document_maintenance()\n\n"
            "storage = lab.StorageService(ds, audit, auth_storage)\n"
            "secure_docs = lab.SecureDocumentService(ds, storage, audit, auth_doc)\n"
            "naive_docs = lab.NaiveDocumentService(storage, auth_doc)\n"
            "app = lab.ResearchApplication(ds, secure_docs, auth_agent, naive_docs, audit)\n"
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
            '    print(f"{pid}: tenant={p.tenant}, ops={list(p.allowed_operations)}, resources={list(p.allowed_resources)}")\n'
            "print('\\n--- Workloads ---')\n"
            "for wid, w in lab.WORKLOAD_REGISTRY.items():\n"
            '    print(f"{wid}: tenant={w.tenant}")'
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
            "my_auth = lab.InfrastructureIdentityProvider.for_document_service()\n"
            "res = storage.read_object_naive(my_auth, 'doc-secret', 'naive-req')\n"
            "assert res == 'Acme acquisition plans.'\n"
            'print(f"Storage Naive Read Result: {res}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 5. Confused Deputy Exploit\n"
            "Because Alice can talk to the Research Agent, and the agent can talk to the Naive Document Service using ambient authority, Alice can trick the agent into retrieving `doc-secret`!"
        ),
        nbf.v4.new_code_cell(
            "auth_alice = lab.ApplicationIdentityProvider.for_alice()\nans = app.answer_naive(auth_alice, 'doc-secret')\nassert 'Acme acquisition plans' in ans\nprint(f\"Exploit Result: {ans}\")"
        ),
        nbf.v4.new_markdown_cell(
            "## 6. Authoritative Principal Resolution\n"
            "A secure delegation issuer accepts provider-verified principal and workload evidence, derives their identifiers, and then resolves authorization attributes from a trusted registry (like Entra ID or Okta). A registry lookup alone does not authenticate the caller."
        ),
        nbf.v4.new_code_cell("principal_id = 'alice'\nprint(f\"Resolving {principal_id} -> {lab.PRINCIPAL_REGISTRY[principal_id]}\")"),
        nbf.v4.new_markdown_cell(
            "## 7. Authoritative Workload Authentication\n"
            "Similarly, a string `caller_id = 'document-service'` isn't proof of identity. Authentication requires trusted infrastructure (mTLS, SPIFFE). Our `InfrastructureIdentityProvider` represents this."
        ),
        nbf.v4.new_code_cell('auth_workload = lab.InfrastructureIdentityProvider.for_document_service()\nprint(f"Authenticated Context: {auth_workload}")'),
        nbf.v4.new_markdown_cell(
            "## 8. Authentication Context Substitution\n"
            "An attacker might transplant a valid context ID onto another identity or recreate all visible fields. "
            "The simulation accepts only the canonical object injected by trusted middleware, so neither attack recreates authentication evidence."
        ),
        nbf.v4.new_code_cell(
            "forged_alice = lab.AuthenticatedPrincipal('alice', auth_bob.auth_context_id)\n"
            'print(f"Forged Principal substitution verified: {lab.ApplicationIdentityProvider.verify(forged_alice)}")\n\n'
            "copied_bob = lab.AuthenticatedPrincipal('bob', 'ctx-bob')\n"
            'print(f"Exact-copy Principal verified: {lab.ApplicationIdentityProvider.verify(copied_bob)}")\n\n'
            "forged_doc = lab.AuthenticatedWorkload('document-service', 'acme', auth_agent.auth_context_id)\n"
            "copied_doc = lab.AuthenticatedWorkload('document-service', 'acme', 'ctx-doc')\n"
            'print(f"Forged Workload substitution verified: {lab.InfrastructureIdentityProvider.verify(forged_doc)}")\n'
            'print(f"Exact-copy Workload verified: {lab.InfrastructureIdentityProvider.verify(copied_doc)}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 9. Delegation Issuance\nWhen Alice makes a request, the app issues a tightly scoped **Delegation Grant** binding Alice to the Research Agent."
        ),
        nbf.v4.new_code_cell(
            "grant_101 = ds.issue(\n"
            "    principal_context=auth_alice,\n"
            "    delegate_context=auth_agent,\n"
            "    audience='document-service', \n"
            "    requested_operations={'read'}, \n"
            "    requested_resources={'doc-101'}\n"
            ")\n"
            "assert grant_101.grant is not None\n"
            'print(f"Issued Grant ID: {grant_101.grant.grant_id}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 10. Forged Principal Attack\n"
            "If an attacker constructs an identity object with copied fields, the issuer rejects it before resolving authorization attributes."
        ),
        nbf.v4.new_code_cell(
            "forged_principal = lab.AuthenticatedPrincipal('alice', 'ctx-alice')\n"
            "fake_grant = ds.issue(forged_principal, auth_agent, 'document-service', {'read'}, {'doc-101'})\n"
            "assert fake_grant.grant is None\n"
            'print(f"Forged Principal Grant: {fake_grant}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 11. Forged Grant Attack\n"
            "If an attacker tries to construct a fake `DelegationGrant` object manually and pass it to a service, the service verifies it against the issuer's store. It will fail."
        ),
        nbf.v4.new_code_cell(
            "fake_obj = lab.DelegationGrant('fake-123', None, 'alice', 'document-service', 'acme', 'storage-service', frozenset({'read'}), frozenset({'doc-secret'}), clock(), clock() + timedelta(minutes=60), 'hacker')\n"
            "decision = ds.verify(fake_obj, 'document-service', 'storage-service', 'acme', 'read', 'doc-secret')\n"
            "assert not decision.allowed\n"
            'print(f"Forged Grant Verification: {decision.reason}")'
        ),
        nbf.v4.new_markdown_cell("## 12. Audience Restriction\nA grant issued for `document-service` cannot be used directly against `storage-service`."),
        nbf.v4.new_code_cell(
            "decision = ds.verify(grant_101.grant, 'research-agent', 'storage-service', 'acme', 'read', 'doc-101')\n"
            "assert decision.reason == 'audience_mismatch'\n"
            'print(f"Audience Mismatch: {decision.reason}")'
        ),
        nbf.v4.new_markdown_cell("## 13. Operation Down-Scoping\nDuring issuance, you cannot request operations the principal doesn't have."),
        nbf.v4.new_code_cell(
            "grant = ds.issue(auth_alice, auth_agent, 'document-service', {'delete'}, {'doc-101'})\nassert grant.grant is None\nprint(f\"Escalated Operation Grant: {grant}\")"
        ),
        nbf.v4.new_markdown_cell("## 14. Resource Down-Scoping\nSimilarly, you cannot request resources the principal doesn't possess."),
        nbf.v4.new_code_cell(
            "grant = ds.issue(auth_alice, auth_agent, 'document-service', {'read'}, {'doc-secret'})\nassert grant.grant is None\nprint(f\"Escalated Resource Grant: {grant}\")"
        ),
        nbf.v4.new_markdown_cell("## 15. Tenant Binding\nA user from Acme cannot delegate a workload from Globex, nor access a Globex resource."),
        nbf.v4.new_code_cell("grant = ds.issue(auth_alice, auth_evil, 'document-service', {'read'}, {'doc-101'})\nassert grant.grant is None\nprint(f\"Cross-tenant delegate: {grant}\")"),
        nbf.v4.new_markdown_cell("## 16. Expiry\nTokens are strictly time-bound."),
        nbf.v4.new_code_cell(
            "grant_exp = ds.issue(auth_alice, auth_agent, 'document-service', {'read'}, {'doc-101'}, ttl_minutes=5)\n"
            "clock.advance(6)\n"
            "decision = ds.verify(grant_exp.grant, 'research-agent', 'document-service', 'acme', 'read', 'doc-101')\n"
            "assert decision.reason == 'delegation_expired'\n"
            'print(f"Expired Token: {decision.reason}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 17. No Ambient-Authority Fallback\nIf delegation fails, the service MUST NOT fall back to its ambient privileges. It must fail closed."
        ),
        nbf.v4.new_code_cell(
            "# Reset clock for valid tests\n"
            "clock.now = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)\n"
            "res = app.answer_secure(auth_alice, 'doc-secret')\n"
            "assert res.terminal_state == 'blocked'\n"
            'print(f"Secure Fail-Closed Result: {res.terminal_state}")\n'
            "events = [e for e in audit.events if e.resource_id == 'doc-secret']\n"
            'print(f"Audit shows DENY: {events[-1].decision} ({events[-1].reason})")'
        ),
        nbf.v4.new_markdown_cell(
            "## 18. Separate Service and Delegated Entry Points\n"
            "Execution mode must come from trusted routing, not request data. The delegated `get_document` method has no `mode` parameter. Background work uses the separate `run_service_read` entry point, which passes the service's infrastructure-authenticated identity to storage."
        ),
        nbf.v4.new_code_cell(
            "try:\n"
            "    secure_docs.get_document(None, None, 'doc-secret', 'req-mode', mode='service')\n"
            "except TypeError as exc:\n"
            '    print(f"Request cannot select service mode: {exc}")\n\n'
            "service_result = secure_docs.run_service_read(auth_job, 'doc-101', 'job-1')\n"
            'print(f"Trusted service entry point: {service_result}")\n'
            'print(f"Service audit: {audit.events[-1].reason}")'
        ),
        nbf.v4.new_markdown_cell("## 19. First Secure Delegated Read\nNow let's see a valid delegated read through the Secure API."),
        nbf.v4.new_code_cell("res = app.answer_secure(auth_alice, 'doc-101', 'req-secure-1')\nassert res.terminal_state == 'answered'\nprint(f\"Valid Secure Read: {res.answer}\")"),
        nbf.v4.new_markdown_cell(
            "## 20. Multi-Hop Token Exchange\n"
            "Notice how the Document Service couldn't use the Research Agent's token for Storage? It had to perform a **Token Exchange**. Let's simulate that manually."
        ),
        nbf.v4.new_code_cell(
            "parent = ds.issue(auth_alice, auth_agent, 'document-service', {'read', 'comment'}, {'doc-101'}, ttl_minutes=60)\n"
            "child = ds.exchange(parent.grant, auth_doc, next_audience='storage-service', requested_operations={'read'}, requested_resources={'doc-101'}, requested_ttl_minutes=10)\n"
            "assert child.grant is not None and child.grant.delegation_depth == 2\n"
            'print(f"Child Audience: {child.grant.audience}")\n'
            'print(f"Child Delegate: {child.grant.delegate_id}")'
        ),
        nbf.v4.new_markdown_cell("## 21. Parent-Child Grant Chain\nThe stateful teaching issuer records a deterministic parent link. This is not a claim that RFC 8693 automatically provides revocation linkage."),
        nbf.v4.new_code_cell('print(f"Parent ID: {parent.grant.grant_id}")\nprint(f"Child Parent ID: {child.grant.parent_grant_id}")'),
        nbf.v4.new_markdown_cell(
            "## 22. Expiry Attenuation\nDuring exchange, a child token cannot outlive its parent. It is clamped to `min(requested_expiry, parent_expiry)`."
        ),
        nbf.v4.new_code_cell(
            "child_long = ds.exchange(parent.grant, auth_doc, 'storage-service', {'read'}, {'doc-101'}, requested_ttl_minutes=120)\n"
            "assert child_long.grant.expires_at == parent.grant.expires_at\n"
            'print(f"Parent Expiry: {parent.grant.expires_at}")\n'
            'print(f"Child Expiry : {child_long.grant.expires_at}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 23. Scope-Expansion Attack\nIf a compromised intermediate service tries to ask for more permissions during exchange, it is denied."
        ),
        nbf.v4.new_code_cell(
            "bad_child = ds.exchange(parent.grant, auth_doc, 'storage-service', {'read', 'delete'}, {'doc-101', 'doc-102'}, requested_ttl_minutes=10)\n"
            "assert bad_child.grant is None\n"
            'print(f"Scope Expansion Result: {bad_child}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 24. Workload Impersonation Attack\n"
            "If an attacker tries to call the backend by simply passing a string ID without an AuthenticatedWorkload context, it fails."
        ),
        nbf.v4.new_code_cell(
            "res = storage.read_object(caller=None, grant=child.grant, resource_id='doc-101', correlation_id='req-impersonate')\n"
            'print(f"Impersonation Result: {res}")\n'
            'print(f"Audit: {audit.events[-1].reason}")'
        ),
        nbf.v4.new_markdown_cell(
            "## 25. Delegation depth and lineage revocation\n"
            "The issuer limits chain length and can revoke an issued lineage for incident containment. This stateful behavior is a deployment choice, not an automatic property of OAuth token exchange."
        ),
        nbf.v4.new_code_cell(
            "too_deep = ds.exchange(child.grant, auth_storage, 'research-agent', {'read'}, {'doc-101'}, 5)\n"
            "assert too_deep.reason == 'maximum_delegation_depth_exceeded'\n"
            "revoked = ds.revoke_lineage(parent.grant.grant_id, 'lab containment')\n"
            "assert revoked.revoked_count >= 2\n"
            "child_decision = ds.verify(child.grant, 'document-service', 'storage-service', 'acme', 'read', 'doc-101')\n"
            "assert child_decision.reason == 'revoked'\n"
            "print('Depth check:', too_deep.reason)\n"
            "print('Revoked grants:', revoked.revoked_count, '| child:', child_decision.reason)"
        ),
        nbf.v4.new_markdown_cell(
            "## 26. Audit/Attribution Trace\n"
            "Let's look at the full audit trace for the successful secure multi-hop request. Notice how identities shift across hops, but Alice is preserved throughout."
        ),
        nbf.v4.new_code_cell(
            "events = [e for e in audit.events if e.correlation_id == 'req-secure-1']\n"
            "for e in events:\n"
            '    print(f"Hop {e.delegation_depth}: {e.workload_id} -> {e.audience} | {e.operation} {e.resource_id} | {e.lifecycle_state}")\n'
            '    print(f"  Principal: {e.principal_id}")\n'
            '    print(f"  Grant Chain: {e.delegation_id} (Parent: {e.parent_delegation_id})\\n")'
        ),
        nbf.v4.new_markdown_cell(
            "## 27. OpenAI Agents SDK: minimal strict tool schema\n"
            "The model selects only a document. Authenticated principal state, tenant, workloads, audiences, grants, scopes, and request IDs stay in server-created `SDKRuntime`. Direct dispatch uses the same application boundary without a model call or API key."
        ),
        nbf.v4.new_code_cell(
            "import json\n"
            "schema = sdk.read_authorized_document.params_json_schema\n"
            "assert set(schema['properties']) == {'document_id'}\n"
            "runtime = sdk.build_runtime('alice')\n"
            "allowed_payload = json.loads(sdk.dispatch_authorized_read(runtime, 'doc-101'))\n"
            "blocked_payload = json.loads(sdk.dispatch_authorized_read(runtime, 'doc-secret'))\n"
            "assert allowed_payload['terminal_state'] == 'answered'\n"
            "assert blocked_payload['terminal_state'] == 'blocked'\n"
            "print(json.dumps(schema, indent=2))\n"
            "print('Allowed:', allowed_payload['terminal_state'], '| blocked:', blocked_payload['terminal_state'])"
        ),
        nbf.v4.new_markdown_cell(
            "## 28. Evaluation: security and utility\n"
            "The release gate measures valid work as well as attacks. Blocking everything is not a useful security system."
        ),
        nbf.v4.new_code_cell(
            "report = lab.evaluate_security_controls()\n"
            "assert report.compliant_success_rate == 1.0\n"
            "assert report.correct_block_rate == 1.0\n"
            "assert report.unsafe_disclosure_count == 0\n"
            "assert report.valid_work_block_count == 0\n"
            "assert report.trace_completeness_rate == 1.0\n"
            "report"
        ),
        nbf.v4.new_markdown_cell(
            "## 29. Adversarial Matrix\n"
            "Run `python3 01_identity_propagation.py` in your terminal to execute the full adversarial scenario set.\n\n"
            "## 30. Exercises\n"
            "1. Extend `AuthenticatedServiceJob` with expiry and revocation, then test exact boundary conditions.\n"
            "2. Inject token-exchange and introspection failures and verify terminal blocked audit events.\n"
            "3. Compare stateful lineage revocation with short-lived self-contained access tokens.\n"
            "4. Explain why a registry lookup authorizes attributes but cannot authenticate a caller.\n\n"
            "## 31. Production Mapping\n"
            "Real token exchange (RFC 8693) uses authorization-server policy and verifiable credentials. Audience restriction and sender-constrained tokens reduce replay risk. JWT validation must pin algorithms and validate issuer, audience, time, and token type. This lab models control semantics with canonical in-memory contexts; production systems must verify signed or opaque credentials at network boundaries.\n\n"
            "References: RFC 8693, RFC 8707, RFC 9700, RFC 8725, SPIFFE Workload API, and the OpenAI Agents SDK guide."
        ),
    ]

    for index, cell in enumerate(nb.cells, start=1):
        cell["id"] = f"identity-propagation-{index:02d}"

    out_path = Path("curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        nbf.write(nb, f)


if __name__ == "__main__":
    create_notebook()
