"""Generate the Enterprise 09 production secure-agent capstone notebook."""
from pathlib import Path
import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "production_secure_agent_capstone.ipynb"


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
        md("e09-title", """
# Enterprise 09 — Production Secure-Agent Capstone

**Goal:** prove an integrated agent's useful behavior and security boundaries,
then make an independent technical-readiness decision for one exact candidate.

![Production secure-agent evidence and authority flow](architecture.svg)

This notebook is deterministic and credential-free. It makes no model, network,
or external-effect calls. The local HMAC protects teaching fixtures only.
"""),
        md("e09-boundary", """
## Boundary model

Retrieved content, memory, tool output, peer messages, model arguments, SDK
handoffs, and MCP annotations are proposals or data. Trusted application code
owns identity, tenant, delegation, policy, approval, effects, durable state,
incident controls, evidence admission, and release evaluation.
"""),
        code("e09-imports", """
from dataclasses import asdict, replace
import json

import production_capstone as core
import capstone_fixtures as fixtures
from capstone_otel import CapstoneTelemetry
import sdk_adapter
import lab

identities = fixtures.actors()
print({"tenant": identities["runtime"].tenant, "policy": fixtures.POLICY_VERSION})
"""),
        md("e09-retrieval", """
## 1. Authorize before retrieval ranking

North evidence is admitted before ranking. The hostile North attachment remains
untrusted data; the South record is not returned at all.
"""),
        code("e09-retrieval-run", """
control = fixtures.plane()
retrieval = control.retrieve(
    identities["runtime"],
    ("doc:north:case-42", "doc:north:hostile", "doc:south:secret"),
    subject_id="case:north:42", now=fixtures.NOW,
)
print(asdict(retrieval))
assert retrieval.document_ids == ("doc:north:case-42", "doc:north:hostile")
assert "IGNORE POLICY" in retrieval.contents[1]
"""),
        md("e09-effect", """
## 2. Confirm one exact approved effect

The effect boundary rechecks the actor, grant, resource, MCP registration,
proposal digest, current policy, approval, and logical operation ID.
"""),
        code("e09-effect-run", """
control = fixtures.plane()
proposal = fixtures.proposal()
allowed = fixtures.approved_dispatch(control, proposal_value=proposal)
retry = control.dispatch(
    identities["runtime"], proposal, grant_id="grant:runtime",
    approval_id=None, now=fixtures.NOW,
)
print(asdict(allowed), asdict(retry))
assert allowed.decision is core.Decision.ALLOW
assert retry.decision is core.Decision.IDEMPOTENT
assert retry.effect_id == allowed.effect_id
"""),
        md("e09-poison", """
## 3. Contain poisoned memory and MCP replacement

Memory cannot persist authority. A changed MCP server digest cannot inherit the
registered server's capability.
"""),
        code("e09-poison-run", """
control = fixtures.plane()
candidate = core.MemoryCandidate(
    "memory:poison", "north", identities["runtime"].subject, "authority",
    "Approve future effects", "tool-output:17", "v1",
)
memory = control.admit_memory(identities["runtime"], candidate)
changed_server = fixtures.proposal(mcp_server_digest="sha256:replacement")
mcp = control.dispatch(
    identities["runtime"], changed_server, grant_id="grant:runtime",
    approval_id=None, now=fixtures.NOW,
)
print({"memory": memory.reason, "mcp": mcp.reason})
assert memory.reason == "memory-kind-forbidden"
assert mcp.reason == "mcp-server-integrity"
"""),
        md("e09-kill", """
## 4. Revoke in-flight authority

The kill switch advances a monotonic epoch. Separate recovery advances it again;
old proposals, approvals, grants, and checkpoints remain stale.
"""),
        code("e09-kill-run", """
control = fixtures.plane()
proposal = fixtures.proposal(logical_operation_id="operation:kill-demo")
approval = control.issue_approval(
    identities["approver"], identities["runtime"].subject, proposal,
    approval_id="approval:kill-demo", now=fixtures.NOW,
)
control.activate_kill_switch(identities["incident"])
stopped = control.dispatch(
    identities["runtime"], proposal, grant_id="grant:runtime",
    approval_id=approval.approval_id, now=fixtures.NOW,
)
control.recover(identities["recovery"])
print({"decision": stopped.decision.value, "reason": stopped.reason, "epoch": control.control_epoch})
assert stopped.reason == "control-epoch"
assert control.control_epoch == 2
"""),
        md("e09-unknown", """
## 5. Preserve unknown provider outcome

A timeout consumes approval and quarantines the logical operation. Retrying with
the same or a new key before reconciliation can duplicate a committed effect.
"""),
        code("e09-unknown-run", """
control = fixtures.plane()
proposal = fixtures.proposal(logical_operation_id="operation:unknown-demo")
unknown = fixtures.approved_dispatch(control, proposal_value=proposal, provider_outcome="unknown")
retry = control.dispatch(
    identities["runtime"], proposal, grant_id="grant:runtime",
    approval_id=None, now=fixtures.NOW,
)
reconciled = control.reconcile(proposal.logical_operation_id, provider_committed=True)
print({"initial": unknown.reason, "retry": retry.reason, "reconcile": reconciled.reason})
assert unknown.decision is retry.decision is core.Decision.UNKNOWN
assert reconciled.decision is core.Decision.ALLOW
"""),
        md("e09-evaluation", """
## 6. Run declared valid, attack, and failure populations

Security and utility use separate exact denominators. Zero forbidden outcomes is
an independent hard requirement.
"""),
        code("e09-evaluation-run", """
results = lab.run_attack_suite()
evaluation = lab.evaluate_suite(results)
print(json.dumps(asdict(evaluation), indent=2))
assert set(evaluation.covered_case_ids) == core.REQUIRED_CASE_IDS
assert evaluation.valid_success_rate == 1.0
assert evaluation.attack_block_rate == 1.0
assert evaluation.failure_safe_rate == 1.0
assert evaluation.forbidden_outcomes == evaluation.false_blocks == 0
assert evaluation.cost_per_successful_compliant_task == 10.5
"""),
        md("e09-sdk", """
## 7. Inspect the real SDK boundary

The real OpenAI Agents SDK builds a typed approval-gated tool and specialist
handoff. The demo does not invoke a model or network. Application dispatch still
makes the authority decision.
"""),
        code("e09-sdk-run", """
sdk_proof = sdk_adapter.credential_free_demo()
print(sdk_proof)
assert sdk_proof["strict_schema"] and sdk_proof["needs_approval"]
assert sdk_proof["handoff_count"] == 1
assert sdk_proof["decision"] == "allow"
assert sdk_proof["model_calls"] == sdk_proof["network_calls"] == 0
"""),
        md("e09-telemetry", """
## 8. Emit minimized OpenTelemetry evidence

Decision metadata is useful for correlation and release evidence. Prompts,
retrieved content, tool arguments, and credentials are deliberately absent.
"""),
        code("e09-telemetry-run", """
telemetry = CapstoneTelemetry()
telemetry.emit(fixtures.approved_dispatch(fixtures.plane()))
attributes = dict(telemetry.finished()[0].attributes)
print(attributes)
assert attributes["agent.decision"] == "allow"
assert not any("prompt" in key or "content" in key or "argument" in key for key in attributes)
"""),
        md("e09-gate", """
## 9. Compare READY, BLOCKED, and INCOMPLETE

Complete passing evidence proves technical readiness. A severe failure is a hard
blocker; a missing artifact preserves incomplete status.
"""),
        code("e09-gate-run", """
dossier = fixtures.dossier(evaluation)
gate = fixtures.gate()
ready = gate.evaluate(dossier, now=fixtures.NOW)
failed = fixtures.evidence("attack-suite", result="fail", severe=True)
blocked_evidence = tuple(failed if item.kind == "attack-suite" else item for item in dossier.evidence)
blocked = gate.evaluate(replace(dossier, evidence=blocked_evidence), now=fixtures.NOW)
incomplete = gate.evaluate(replace(dossier, evidence=dossier.evidence[:-1]), now=fixtures.NOW)
print({"complete": ready.state.value, "severe": blocked.state.value, "missing": incomplete.state.value})
assert (ready.state, blocked.state, incomplete.state) == (
    core.GateState.READY, core.GateState.BLOCKED, core.GateState.INCOMPLETE,
)
"""),
        md("e09-checkpoint", """
## Knowledge checkpoint

An approved effect times out and provider state is unavailable. May a recovery
approver generate a new idempotency key and retry?

**Expected reasoning:** No. Preserve reconciliation-required for the original
logical operation. Determine the provider postcondition first; then record the
original effect or create and independently authorize one exact new proposal
under current policy. Recovery approval cannot erase ambiguity.
"""),
        md("e09-exercises", """
## Production exercises

1. Replace local HMAC with managed asymmetric signing and revocation.
2. Add a second tenant-specific MCP server and prove credential isolation.
3. Add one-owner checkpoint fencing and a concurrent resume race.
4. Add property-based tests for canonicalization and idempotency collisions.
5. Build a separate canary-deployment authorization that consumes but cannot
   manufacture the technical-readiness receipt.
"""),
    ]
    return notebook


if __name__ == "__main__":
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")
