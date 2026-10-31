"""Generate the Advanced 03 notebook from deterministic source cells."""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "cascade_blast_radius.ipynb"


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
            "a03-title",
            """
# Advanced 03 — Cascading Failures and Blast-Radius Control

**Goal:** keep one failed or poisoned worker from becoming recursive work,
retry amplification, queue exhaustion, or duplicated effects across an agent
graph. This notebook exercises the tested controller and real OpenAI Agents
SDK adapter without credentials, a model call, or network access.

![One shared cascade budget bounds the graph](architecture.svg)
""",
        ),
        markdown(
            "a03-contract",
            """
## Security and reliability contract

The model proposes work. Trusted application code owns authenticated graph
edges, one shared depth/fan-out/dispatch/retry budget, queue bulkheads, circuit
state, containment, and effects. Every attempt reserves budget before enqueue,
and every effect cites a successful bound attempt.
""",
        ),
        code(
            "a03-imports",
            """
from dataclasses import asdict
import asyncio

import lab
import sdk_adapter as sdk
""",
        ),
        markdown(
            "a03-baseline-heading",
            """
## 1. Reproduce positive feedback

When three layers each make three retries after the initial call, independent
local policies can create `4³ = 64` attempts. This baseline is deliberately
unsafe and performs no real effect.
""",
        ),
        code(
            "a03-baseline",
            """
comparison = lab.unsafe_naive_cascade(retries_per_layer=3, retrying_layers=3)
print(asdict(comparison))
assert comparison.unsafe_attempts == 64
assert comparison.unsafe_affected_components == 4
assert comparison.unsafe_unauthorized_effects == 2
""",
        ),
        markdown(
            "a03-fanout-heading",
            """
## 2. Admit bounded fan-out

Three valid logical branches remain usable. Identity, tenant, parent, worker,
task type, payload digest, graph depth, and budget are checked before enqueue.
""",
        ),
        code(
            "a03-fanout",
            """
controller, identities = lab.build_scenario()
run = lab.start_run(controller, identities)
for index, target in enumerate(("research", "billing", "ticket"), start=1):
    dispatched, observed = lab.dispatch_and_observe(
        controller, identities, run, target,
        attempt_id=f"attempt:notebook:{target}",
        outcome=lab.Outcome.SUCCESS,
        step=index * 2 - 1,
    )
    assert dispatched.allowed and observed.allowed
completed = controller.complete(run.root.run_id, step=8)
print({
    "completion": completed.reason,
    "affected_components": sorted(run.affected_components),
    "dispatches": len(run.attempts),
})
assert completed.allowed and len(run.affected_components) == 3
""",
        ),
        markdown(
            "a03-bulkhead-heading",
            """
## 3. Fill one queue, not the whole system

The per-component queue is a bulkhead. Its capacity is separate from the
circuit breaker and from the graph-wide dispatch budget.
""",
        ),
        code(
            "a03-bulkhead",
            """
bulkheads, identities = lab.build_scenario()
bulkhead_run = lab.start_run(bulkheads, identities, run_id="run:bulkhead")
for index in (1, 2):
    proposal = lab.dispatch_for(
        bulkhead_run, identities, "research",
        attempt_id=f"attempt:queue:{index}",
        logical_id=f"logical:queue:{index}",
    )
    assert bulkheads.dispatch(
        identities["supervisor"], bulkhead_run.root.run_id, proposal, step=index
    ).allowed
third = bulkheads.dispatch(
    identities["supervisor"], bulkhead_run.root.run_id,
    lab.dispatch_for(
        bulkhead_run, identities, "research",
        attempt_id="attempt:queue:3", logical_id="logical:queue:3"
    ),
    step=3,
)
print({"state": third.state.value, "reason": third.reason,
       "research_queue": len(bulkhead_run.queues["research"])})
assert third.reason == "component-queue-full"
assert len(bulkhead_run.queues["billing"]) == 0
""",
        ),
        markdown(
            "a03-retry-heading",
            """
## 4. Centralize retries and isolate circuits

Only an observed transient failure is retryable. Repeated billing failures
open billing’s circuit; they do not close research.
""",
        ),
        code(
            "a03-retry-circuit",
            """
resilience, identities = lab.build_scenario()
resilience_run = lab.start_run(resilience, identities, run_id="run:resilience")
for index in (1, 2):
    lab.dispatch_and_observe(
        resilience, identities, resilience_run, "billing",
        attempt_id=f"attempt:billing:{index}",
        logical_id=f"logical:billing:{index}",
        outcome=lab.Outcome.TRANSIENT_FAILURE,
        step=index * 2 - 1,
    )
blocked = resilience.dispatch(
    identities["supervisor"], resilience_run.root.run_id,
    lab.dispatch_for(
        resilience_run, identities, "billing",
        attempt_id="attempt:billing:blocked",
        logical_id="logical:billing:blocked",
    ),
    step=5,
)
research, _ = lab.dispatch_and_observe(
    resilience, identities, resilience_run, "research",
    attempt_id="attempt:research:isolated",
    outcome=lab.Outcome.SUCCESS,
    step=6,
)
print({"billing": blocked.reason, "research": research.reason})
assert blocked.reason == "circuit-open" and research.allowed
""",
        ),
        markdown(
            "a03-containment-heading",
            """
## 5. Contain poison in the observation transition

Poison is not retried. The controller marks the run contained, clears every
queue, and blocks subsequent effects under the same run state.
""",
        ),
        code(
            "a03-containment",
            """
contained_controller, contained_run, contained = lab.controlled_poison_cascade()
print({
    "state": contained.state.value,
    "reason": contained.reason,
    "queues": {name: len(queue) for name, queue in contained_run.queues.items()},
    "stop_latency_steps": contained_run.contained_step - contained_run.trigger_step,
})
assert contained.reason == "poison-contained"
assert all(not queue for queue in contained_run.queues.values())
assert contained_run.contained_step - contained_run.trigger_step == 0
assert len(contained_run.effects) == 0
""",
        ),
        markdown(
            "a03-effects-heading",
            """
## 6. Execute a successful effect once

The ticket worker can create one internal ticket only after its bound attempt
succeeds. Replaying the identical operation returns the stored effect.
""",
        ),
        code(
            "a03-effects",
            """
effects, identities = lab.build_scenario()
effect_run = lab.start_run(effects, identities, run_id="run:effect")
dispatched, _ = lab.dispatch_and_observe(
    effects, identities, effect_run, "ticket",
    attempt_id="attempt:ticket:success",
    outcome=lab.Outcome.SUCCESS,
    step=1,
)
proposal = lab.EffectProposal(
    "operation:ticket:notebook",
    "create-internal-ticket",
    "case:north:42",
    dispatched.attempt.proposal.attempt_id,
)
first = effects.authorize_effect(identities["ticket"], effect_run.root.run_id, proposal, step=3)
replay = effects.authorize_effect(identities["ticket"], effect_run.root.run_id, proposal, step=4)
print({"first": first.reason, "replay": replay.reason,
       "stored_effects": len(effect_run.effects)})
assert first.allowed and replay.replayed and len(effect_run.effects) == 1
""",
        ),
        markdown(
            "a03-sdk-heading",
            """
## 7. Exercise the real OpenAI Agents SDK boundary

The strict model-facing tool accepts only an untrusted note. Worker, task,
tenant, depth, retry relation, and budget remain in application context.
Framework loop limits are defense in depth, not the policy boundary.
""",
        ),
        code(
            "a03-sdk",
            """
sdk_result = await sdk.credential_free_demo()
schema_fields = set(sdk_result["tool_schema"]["properties"])
print({
    "tool": sdk_result["tool_names"],
    "schema_fields": sorted(schema_fields),
    "parallel_tool_calls": sdk_result["parallel_tool_calls"],
    "runner_limits": sdk_result["runner_limits"],
    "decision": sdk_result["decision"],
    "model_calls": sdk_result["model_calls"],
    "network_calls": sdk_result["network_calls"],
})
assert schema_fields == {"task_note"}
assert sdk_result["parallel_tool_calls"] is False
assert sdk_result["model_calls"] == sdk_result["network_calls"] == 0
""",
        ),
        markdown(
            "a03-evaluation-heading",
            """
## 8. Evaluate valid, attack, and failure populations separately

The controlled system must preserve valid utility, create no forbidden attack
effect, surface dependency outages as errors, and produce complete terminal
evidence. Severe cases are not averaged away.
""",
        ),
        code(
            "a03-evaluation",
            """
report, cases = lab.evaluate_controls()
print(asdict(report))
print({population: sum(case.population == population for case in cases)
       for population in ("valid", "attack", "failure")})
assert (report.valid_cases, report.attack_cases, report.failure_cases) == (5, 12, 3)
assert report.valid_completion_rate == 1.0
assert report.attack_forbidden_effect_rate == 0.0
assert report.failure_error_rate == 1.0
assert report.max_affected_components == 3
assert report.max_stop_latency_steps == 0
assert report.controlled_retry_amplification == 2.0
assert report.unsafe_retry_amplification == 64.0
assert report.trace_completeness_rate == 1.0
""",
        ),
        markdown(
            "a03-production",
            """
## Production replacement checklist

Replace fixture identities with workload identity; the in-memory ledger with a
transactional store and outbox; Python queues with bounded broker partitions;
the local effect map with a unique operation constraint and reconciliation;
logical steps with monotonic time and traces; and the local kill switch with
lease revocation, queue quarantine, and effect fencing. Preserve redacted
decision receipts across every replacement.

## Checkpoint

Why is a retry policy applied independently by every SDK, worker, connector,
and queue dangerous?

**Because local limits multiply across graph layers.** Use one trusted retry
owner with per-root and per-logical budgets, transient-only eligibility, an
end-to-end deadline, bulkheads, circuits, and idempotent effects.
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
