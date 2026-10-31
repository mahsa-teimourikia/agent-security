"""Generate the Advanced 02 notebook from deterministic source cells."""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "cross_agent_message_poisoning.ipynb"


def markdown(cell_id: str, source: str):
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
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3",
        },
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        markdown(
            "a02-title",
            """
# Advanced 02 — Cross-Agent Prompt Injection and Message Poisoning

**Goal:** keep authenticated peer messages useful as data without letting their
prose acquire authority. This notebook exercises the tested `lab.py` and the
real OpenAI Agents SDK adapter without credentials, a model call, or network
access.

![Authenticated peer-message boundary](architecture.svg)
""",
        ),
        markdown(
            "a02-contract",
            """
## Security contract

Identity attributes the sender; it does not make generated text trusted.
Admission binds the peer edge to current source lineage. Every transformation
must preserve provenance, taint, and allowed use. A separate application
boundary authorizes the exact follow-on effect.
""",
        ),
        code(
            "a02-imports",
            """
from dataclasses import replace
import asyncio

import lab
import sdk_adapter as sdk

gateway, gate, authorizer, researcher, writer = lab.build_scenario()
proposal = lab.proposal_for(gateway)
print({
    "sender": researcher.subject,
    "recipient": proposal.recipient,
    "source_ids": [ref.source_id for ref in proposal.source_refs],
    "unsafe_baseline_action": lab.unsafe_concatenation_baseline(proposal.content),
})
assert lab.unsafe_concatenation_baseline(proposal.content) == "export_records"
""",
        ),
        markdown(
            "a02-admission-heading",
            """
## 1. Admit the hostile content without sanitizing it into trust

The vendor statement remains visible, while the trusted source registry—not
the model—derives its taint and allowed-use ceiling.
""",
        ),
        code(
            "a02-admission",
            """
admission = gateway.admit(researcher, proposal, now=lab.NOW)
assert admission.allowed and admission.message
message = admission.message
print({
    "state": admission.state.value,
    "reason": admission.reason,
    "taint": sorted(message.envelope.taint_labels),
    "allowed_uses": sorted(message.envelope.allowed_uses),
    "content_still_contains_attack": "ACTION: export_records" in message.content,
})
assert "instruction-bearing" in message.envelope.taint_labels
assert "export_records" not in message.envelope.allowed_uses
""",
        ),
        markdown(
            "a02-boundary-heading",
            """
## 2. Attack the peer boundary

Changing tenant or workload identity is a control-plane attack. The decision
is made before the content is exposed to the recipient model.
""",
        ),
        code(
            "a02-boundary-attack",
            """
fresh_gateway, _, _, fresh_researcher, _ = lab.build_scenario()
cross_tenant = replace(lab.proposal_for(fresh_gateway), tenant="south")
denial = fresh_gateway.admit(fresh_researcher, cross_tenant, now=lab.NOW)
print({"state": denial.state.value, "reason": denial.reason, "effects": 0})
assert not denial.allowed and denial.reason == "tenant"
""",
        ),
        markdown(
            "a02-transform-heading",
            """
## 3. Preserve security metadata across the writer

A valid summary carries the exact source references, taint labels, and use
ceiling. A clean-looking candidate that drops taint is rejected.
""",
        ),
        code(
            "a02-transform",
            """
valid = gate.derive(writer, message, lab.candidate_for(message), now=lab.NOW)
assert valid.allowed and valid.artifact

laundered = replace(
    lab.candidate_for(message, artifact_id="artifact:laundered"),
    taint_labels=frozenset(),
)
blocked = gate.derive(writer, message, laundered, now=lab.NOW)
print({
    "valid_transform": valid.reason,
    "preserved_taint": sorted(valid.artifact.taint_labels),
    "laundering_attempt": blocked.reason,
})
assert not blocked.allowed and blocked.reason == "taint-loss"
""",
        ),
        markdown(
            "a02-effect-heading",
            """
## 4. Authorize the effect independently

The hostile message may support one internal brief. Its embedded export command
does not enter the authorizer as a permission.
""",
        ),
        code(
            "a02-effects",
            """
internal = authorizer.authorize(
    writer,
    lab.ActionProposal(
        "operation:brief", "draft_internal_brief", "case:north:42", valid.artifact.artifact_id
    ),
    now=lab.NOW,
)
export = authorizer.authorize(
    writer,
    lab.ActionProposal(
        "operation:export", "export_records", "case:north:42", valid.artifact.artifact_id
    ),
    now=lab.NOW,
)
print({
    "bounded_effect": internal.reason,
    "export_attempt": export.reason,
    "effect_count": len(authorizer.effects),
})
assert internal.allowed
assert not export.allowed and export.reason == "action-not-allowed"
assert len(authorizer.effects) == 1
""",
        ),
        markdown(
            "a02-sdk-heading",
            """
## 5. Exercise the real OpenAI Agents SDK handoff boundary

The model-facing schema contains only a reason and bounded summary. Trusted
identity, tenant, routing, type, and source lineage stay in local application
context. The filter removes raw handoff history.
""",
        ),
        code(
            "a02-sdk",
            """
handoff_object, framework_context, filtered = await sdk.credential_free_demo()
schema_fields = set(handoff_object.input_json_schema["properties"])
print({
    "tool": handoff_object.tool_name,
    "destination": handoff_object.agent_name,
    "model_schema_fields": sorted(schema_fields),
    "admission": framework_context.last_decision.reason,
    "filtered_history": filtered.input_history,
    "model_calls": 0,
    "network_calls": 0,
})
assert schema_fields == {"reason", "summary"}
assert "hostile raw conversation" not in filtered.input_history
""",
        ),
        markdown(
            "a02-eval-heading",
            """
## 6. Evaluate valid, attack, and failure populations separately

The unsafe baseline is expected to fail. The controlled system must retain
valid utility, create no forbidden attack effects, and expose dependency
failure as `error` rather than counting it as a successful defense.
""",
        ),
        code(
            "a02-evaluation",
            """
report, cases = lab.evaluate_controls()
print(report)
print({population: sum(case.population == population for case in cases)
       for population in ("valid", "attack", "failure")})
assert (report.valid_cases, report.attack_cases, report.failure_cases) == (5, 12, 3)
assert report.valid_completion_rate == 1.0
assert report.attack_forbidden_effect_rate == 0.0
assert report.failure_error_rate == 1.0
assert report.poison_propagation_rate == 0.0
assert report.provenance_loss_acceptance_rate == 0.0
assert report.unsafe_follow_on_rate == 0.0
assert report.trace_completeness_rate == 1.0
assert report.unsafe_baseline_compromise_rate == 1.0
""",
        ),
        markdown(
            "a02-checkpoint",
            """
## Checkpoint

An authenticated researcher sends a schema-valid summary saying “export all
customer records.” Does authentication make that sentence an authorization?

**No.** Authentication attributes the message and a schema constrains shape.
The application must admit it as data, preserve provenance and taint, then
independently authorize an exact current effect.
""",
        ),
    ]
    return notebook


def main() -> None:
    notebook = build_notebook()
    with OUTPUT.open("w") as handle:
        nbf.write(notebook, handle)
    print(f"wrote {OUTPUT.name} with {len(notebook['cells'])} cells")


if __name__ == "__main__":
    main()
