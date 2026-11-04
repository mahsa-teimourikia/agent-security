"""Generate the Enterprise 06 notebook deterministically."""
from pathlib import Path
import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "governance_inventory.ipynb"


def md(cell_id: str, source: str):
    cell = nbf.v4.new_markdown_cell(source.strip())
    cell["id"] = cell_id
    return cell


def code(cell_id: str, source: str):
    cell = nbf.v4.new_code_cell(source.strip())
    cell["id"] = cell_id
    return cell


def build_notebook():
    notebook = nbf.v4.new_notebook()
    notebook["metadata"] = {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        md("e06-title", """
# Enterprise 06 — Agent Security Governance

**Goal:** admit evidence for one exact agent revision, reach a deterministic
governance decision, and authorize one lifecycle transition without allowing
stale changes, self-approval, or exceptions to erase hard blockers.

![Governance evidence and lifecycle control plane](architecture.svg)

This notebook is deterministic, credential-free, and makes no external calls.
"""),
        md("e06-thesis", """
## Security thesis

An inventory row is not authority. Trusted application code must bind an agent's
tenant, revision, owners, autonomy, effects, dependencies, policy, and evidence;
then require current operator authority and a separate, exact, single-use approval.
"""),
        code("e06-imports", """
from dataclasses import asdict, replace
import json

import governance as gov
import governance_fixtures as fx
import governance_pydantic_adapter as adapter

record = fx.record()
print({"agent": record.agent_id, "revision": record.revision, "tier": record.risk_tier.value})
"""),
        md("e06-schema", """
## 1. Validate hostile inventory JSON

Pydantic v2 rejects unknown fields and coercion. Shape validation is useful,
but it does not authenticate the submitter or establish that the claims are true.
"""),
        code("e06-schema-run", """
parsed = adapter.parse_record(asdict(record))
assert parsed == record
try:
    adapter.parse_record({**asdict(record), "model_generated_approval": True})
except Exception as error:
    print(type(error).__name__, "unknown field rejected")
"""),
        md("e06-admission", """
## 2. Admit producer-scoped evidence

Admission checks producer, key, tenant, allowed kind, proof, counts, time shape,
and conflicting redelivery before evidence can affect governance.
"""),
        code("e06-admission-run", """
store = fx.store([])
item = fx.evidence("security-test")
receipt = store.admit(item, fx.NOW)
tampered = store.admit(replace(item, passed=99), fx.NOW)
print(asdict(receipt), asdict(tampered))
assert receipt.admitted and tampered.reason == "invalid-proof"
"""),
        md("e06-decision", """
## 3. Evaluate the exact revision

High-risk authorization requires threat-model, security-test, privacy-review,
and incident-drill evidence. Severe failures remain outside aggregate scores.
"""),
        code("e06-decision-run", """
engine = fx.engine()
decision = engine.evaluate(record, gov.Lifecycle.AUTHORIZED, fx.NOW)
print(json.dumps(asdict(decision), indent=2, default=lambda value: value.value))
assert decision.state is gov.DecisionState.READY
"""),
        md("e06-approval", """
## 4. Consume separate, exact authority

The operator's current tenant-scoped role is checked before a different actor's
signed approval is consumed. Reuse fails.
"""),
        code("e06-approval-run", """
approval = fx.approval(decision)
authorized = engine.authorize(record, decision, approval, fx.operator(), fx.NOW)
print({"state": authorized.lifecycle.value, "revision": authorized.revision})
assert authorized.revision == 8
try:
    engine.authorize(record, decision, approval, fx.operator(), fx.NOW)
except PermissionError as error:
    print(error)
"""),
        md("e06-change", """
## 5. Invalidate stale evidence after material change

A new refund tool changes the authority surface. Incrementing the record revision
makes every revision-7 artifact inapplicable to revision 8.
"""),
        code("e06-change-run", """
changed = replace(record, revision=8, tools=record.tools + ("refund.issue",), change_digest="change-8")
stale = fx.engine().evaluate(changed, gov.Lifecycle.AUTHORIZED, fx.NOW)
print(stale.state.value, stale.blockers)
assert stale.state is gov.DecisionState.INCOMPLETE
"""),
        md("e06-exception", """
## 6. Keep severe outcomes non-waivable

Even an authentic, owned, current exception cannot remove the hard floor.
"""),
        code("e06-exception-run", """
items = [fx.evidence("security-test", severe_failures=1, passed=99)] + [
    fx.evidence(kind) for kind in ("threat-model", "privacy-review", "incident-drill")]
blocked = fx.engine(items).evaluate(
    record, gov.Lifecycle.AUTHORIZED, fx.NOW, [fx.exception("severe-failure")])
print(blocked.blockers)
assert "severe-failure" in blocked.blockers
"""),
        md("e06-concurrency", """
## 7. Reject stale inventory writers

Optimistic concurrency prevents a stale browser tab or automation from silently
erasing a newer ownership, permission, or lifecycle decision.
"""),
        code("e06-concurrency-run", """
inventory = gov.Inventory()
inventory.put(replace(record, revision=1), None)
inventory.put(replace(record, revision=2), 1)
try:
    inventory.put(replace(record, revision=2, purpose="stale overwrite"), 1)
except RuntimeError as error:
    print(error)
"""),
        md("e06-checkpoint", """
## Checkpoint

A complete catalog row says an agent is low risk. Deployment discovery shows a
new payment tool and a production identity, but the last evidence set predates
both. May the catalog owner approve production?

**Expected reasoning:** No. Reconcile the actual authority surface, create a new
record revision, reclassify risk through trusted policy, collect evidence for
that exact revision, and require a separate current approval. Completeness and
catalog ownership do not establish production authority.
"""),
    ]
    return notebook


if __name__ == "__main__":
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")
