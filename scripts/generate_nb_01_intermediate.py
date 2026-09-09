import nbformat as nbf
from pathlib import Path

def create_notebook():
    nb = nbf.v4.new_notebook()
    
    nb.cells = [
        nbf.v4.new_markdown_cell("# Intermediate 01: Identity Propagation and Delegated Authority\n\nIn simple systems, knowing *who is calling* is easy. In agentic architectures, a request might hop from the User -> Agent -> Document Service -> Storage Service.\n\nIf the Agent uses its own powerful infrastructure privileges to fetch data, it can be tricked into retrieving documents the original User isn't allowed to see. This is the **Confused Deputy** problem.\n\nThe solution is **Identity Propagation**: securely passing the user's identity and a tightly scoped **Delegation Grant** all the way down the chain."),
        
        nbf.v4.new_code_cell(
            "import sys\n"
            "from pathlib import Path\n"
            "import importlib\n"
            "sys.path.append(str(Path.cwd().parent.parent.parent / 'curriculum' / 'intermediate' / '01-identity-propagation'))\n"
            "lab = importlib.import_module('01_identity_propagation')\n"
            "from datetime import datetime, timezone, timedelta\n\n"
            "clock = lambda: datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)\n"
            "ds = lab.DelegationService(clock_fn=clock)\n"
            "audit = lab.AuditSink()\n"
            "storage = lab.StorageService(ds, audit)\n"
            "secure_docs = lab.SecureDocumentService(ds, storage, audit)\n"
            "naive_docs = lab.NaiveDocumentService(storage)\n"
            "app = lab.ResearchApplication(ds, secure_docs, naive_docs, audit)\n"
        ),
        
        nbf.v4.new_markdown_cell("## 1. The Confused Deputy (Ambient Authority)\n\nFirst, let's see how a naive service behaves. The `NaiveDocumentService` trusts the Research Agent's workload identity completely. It uses its *ambient* service-level authority to query storage, ignoring the user.\n\nAlice only has access to `doc-101` and `doc-102`. But watch what happens when she asks for `doc-secret` through the naive API:"),
        
        nbf.v4.new_code_cell(
            "ans = app.answer_naive(\"alice\", \"doc-secret\")\n"
            "print(f\"Result: {ans}\")"
        ),
        
        nbf.v4.new_markdown_cell("Because the downstream service only saw `research-agent`, it happily returned the highly classified acquisition plans. The agent was tricked into bypassing Alice's restrictions.\n\n## 2. Secure Identity Propagation\n\nNow, let's use the secure API. Here, the `ResearchApplication` issues a **Delegation Grant** to the agent. This grant binds Alice (Principal) to the Agent (Delegate), restricted to `doc-secret`.\n\nHowever, the Issuer will enforce *monotonic down-scoping*: it will **refuse to issue a grant for a resource Alice does not already possess**."),
        
        nbf.v4.new_code_cell(
            "r_allowed = app.answer_secure(\"alice\", \"doc-101\", \"req-allowed\")\n"
            "r_denied = app.answer_secure(\"alice\", \"doc-secret\", \"req-denied\")\n\n"
            "print(f\"Doc-101 (Allowed): {r_allowed.answer}\")\n"
            "print(f\"Doc-Secret (Denied): {r_denied.answer}\")"
        ),
        
        nbf.v4.new_markdown_cell("## 3. Delegation Audit Trail\n\nLet's inspect the secure multi-hop audit trail for `req-allowed`. Notice how both the Workload Identity (who is acting) and the Audience (who they are talking to) shift at each hop, while Alice (Principal) is preserved throughout."),
        
        nbf.v4.new_code_cell(
            "events = [e for e in audit.events if e.correlation_id == \"req-allowed\"]\n"
            "for e in events:\n"
            "    print(f\"Hop {e.delegation_depth}:\")\n"
            "    print(f\"  Principal: {e.principal_id}\")\n"
            "    print(f\"  Delegate:  {e.workload_id}\")\n"
            "    print(f\"  Audience:  {e.audience}\")\n"
            "    print(f\"  Action:    {e.operation} {e.resource_id}\")\n"
            "    print(f\"  Decision:  {e.decision} ({e.reason})\\n\")"
        ),
        
        nbf.v4.new_markdown_cell("## 4. Audience Restriction and Scope\n\nIf an attacker steals a token meant for the Document Service and tries to replay it against the Storage Service directly, it will fail due to **Audience Mismatch**. If they try to modify a document with a read-only token, it fails due to **Scope Mismatch**."),
        
        nbf.v4.new_code_cell(
            "alice = lab.PRINCIPAL_REGISTRY[\"alice\"]\n"
            "agent = lab.WORKLOAD_REGISTRY[\"research-agent\"]\n\n"
            "# 1. Create a grant intended for the Document Service\n"
            "grant = ds.issue(alice, agent, audience=\"document-service\", requested_operations={\"read\"}, requested_resources={\"doc-101\"})\n\n"
            "# 2. Attempt to use it directly against Storage Service (Wrong Audience)\n"
            "res = storage.read_object(\"research-agent\", grant, \"doc-101\", \"req-steal\")\n"
            "print(f\"Storage response: {res}\")\n"
            "print(f\"Audit Reason: {audit.events[-1].reason}\")"
        )
    ]
    
    out_path = Path("curriculum/intermediate/01-identity-propagation/01_identity_propagation.ipynb")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        nbf.write(nb, f)

if __name__ == "__main__":
    create_notebook()
