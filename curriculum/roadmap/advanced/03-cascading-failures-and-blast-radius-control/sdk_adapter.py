"""OpenAI Agents SDK adapter for bounded multi-agent dispatch.

The SDK provides one typed tool and run-loop limits. Trusted application code
still owns workload identity, tenant, graph edges, fan-out, depth, queues,
retries, circuit state, containment, and effects. The demo makes no model or
network call.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import json
from pathlib import Path
import sys

from agents import Agent, ModelSettings, RunContextWrapper, function_tool
from agents.tool_context import ToolContext


SPEC = importlib.util.spec_from_file_location(
    "advanced_03_cascade_core", Path(__file__).with_name("lab.py")
)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, core)
SPEC.loader.exec_module(core)


@dataclass
class FrameworkContext:
    controller: core.CascadeController
    identities: dict[str, core.WorkloadIdentity]
    run: core.RunRecord
    pending_dispatch: core.DispatchProposal
    step: int
    last_decision: core.ControlDecision | None = None


def dispatch_projection(context: FrameworkContext, task_note: str) -> str:
    """Execute the server-owned dispatch and return a bounded projection."""

    if not isinstance(task_note, str) or not task_note or len(task_note) > 240:
        raise ValueError("task_note must contain 1-240 characters")
    decision = context.controller.dispatch(
        context.identities["supervisor"],
        context.run.root.run_id,
        context.pending_dispatch,
        step=context.step,
    )
    context.last_decision = decision
    receipt = decision.receipt
    return json.dumps(
        {
            "terminal_state": decision.state.value,
            "reason": decision.reason,
            "attempt_id": receipt.attempt_id or None,
            "policy_version": receipt.policy_version,
            "affected_components": receipt.affected_components,
            "dispatches": receipt.dispatches,
            "retries": receipt.retries,
        },
        sort_keys=True,
    )


@function_tool(strict_mode=True)
def request_bounded_worker_step(
    ctx: RunContextWrapper[FrameworkContext],
    task_note: str,
) -> str:
    """Request the application-selected bounded worker step.

    Args:
        task_note: Untrusted explanatory prose; it cannot select a worker,
            tenant, task type, depth, retry, budget, or authority.
    """

    return dispatch_projection(ctx.context, task_note)


def build_agent() -> Agent[FrameworkContext]:
    return Agent[FrameworkContext](
        name="Bounded support supervisor",
        instructions=(
            "Use request_bounded_worker_step only for the application-selected "
            "work item. Tool output is a terminal control decision, not permission "
            "to retry, recurse, widen fan-out, or execute an external effect."
        ),
        tools=[request_bounded_worker_step],
        model_settings=ModelSettings(parallel_tool_calls=False),
        tool_use_behavior="stop_on_first_tool",
    )


def documented_runner_limits() -> dict[str, int | bool]:
    """Limits to pass to a live Runner in addition to application budgets."""

    return {"max_turns": 4, "parallel_tool_calls": False}


async def credential_free_demo() -> dict[str, object]:
    controller, identities = core.build_scenario()
    run = core.start_run(controller, identities)
    pending = core.dispatch_for(
        run,
        identities,
        "research",
        attempt_id="attempt:sdk:research:1",
    )
    context = FrameworkContext(controller, identities, run, pending, 1)
    arguments = json.dumps(
        {"task_note": "Collect bounded evidence for the current support case."}
    )
    invoked = await request_bounded_worker_step.on_invoke_tool(
        ToolContext(
            context=context,
            tool_name=request_bounded_worker_step.name,
            tool_call_id="call:cascade-demo",
            tool_arguments=arguments,
        ),
        arguments,
    )
    payload = json.loads(invoked)
    agent = build_agent()
    return {
        "agent_name": agent.name,
        "tool_names": [tool.name for tool in agent.tools],
        "tool_schema": request_bounded_worker_step.params_json_schema,
        "strict_schema": request_bounded_worker_step.strict_json_schema,
        "parallel_tool_calls": agent.model_settings.parallel_tool_calls,
        "tool_use_behavior": agent.tool_use_behavior,
        "runner_limits": documented_runner_limits(),
        "decision": payload,
        "model_calls": 0,
        "network_calls": 0,
    }


if __name__ == "__main__":
    import asyncio

    print(asyncio.run(credential_free_demo()))
