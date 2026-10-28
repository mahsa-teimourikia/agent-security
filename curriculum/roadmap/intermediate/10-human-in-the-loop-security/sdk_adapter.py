"""Credential-free OpenAI Agents SDK HITL adapter for Intermediate 10.

The real SDK supplies a deterministic interruption and serializable ``RunState``
through ``ScriptedModel``.  The course control plane still owns reviewer
authentication, exact approval, reauthorization, and the effect boundary.
"""

from __future__ import annotations

import asyncio
from importlib.metadata import version
import importlib.util
import json
from pathlib import Path
import sys
from typing import Annotated, Any

from agents import Agent, RunState, Runner, function_tool
from agents.testing import ScriptedModel, function_call
from pydantic import Field


LAB_SPEC = importlib.util.spec_from_file_location(
    "intermediate_10_hitl_lab", Path(__file__).with_name("lab.py")
)
assert LAB_SPEC and LAB_SPEC.loader
if LAB_SPEC.name in sys.modules:
    lab = sys.modules[LAB_SPEC.name]
else:
    lab = importlib.util.module_from_spec(LAB_SPEC)
    sys.modules[LAB_SPEC.name] = lab
    LAB_SPEC.loader.exec_module(lab)


TOOL_EXECUTIONS: list[str] = []


@function_tool(needs_approval=True, strict_mode=True)
def issue_refund(
    resource_id: Annotated[str, Field(min_length=1, max_length=64)],
    amount_cents: Annotated[int, Field(gt=0, le=10_000)],
    currency: Annotated[str, Field(pattern="^CAD$")],
    reason: Annotated[str, Field(min_length=1, max_length=500)],
    logical_operation_id: Annotated[str, Field(min_length=1, max_length=80)],
) -> str:
    """Unsafe alternate path: course tests require this function never to run."""

    TOOL_EXECUTIONS.append(logical_operation_id)
    raise RuntimeError("SDK workflow approval is not the application effect boundary")


def _proposal(arguments: dict[str, Any]) -> lab.ActionProposal:
    return lab.ActionProposal(
        request_id="sdk-request:42",
        run_id="sdk-run:42",
        operation="issue_refund",
        resource_id=arguments["resource_id"],
        amount_cents=arguments["amount_cents"],
        currency=arguments["currency"],
        reason=arguments["reason"],
        logical_operation_id=arguments["logical_operation_id"],
    )


async def run_sdk_demo() -> dict[str, object]:
    """Create a real SDK interruption, round-trip it, and use the trusted gate."""

    TOOL_EXECUTIONS.clear()
    arguments = {
        "resource_id": "case:north:42",
        "amount_cents": 2_500,
        "currency": "CAD",
        "reason": "Customer received a damaged shipment.",
        "logical_operation_id": "sdk-refund:42:1",
    }
    model = ScriptedModel(
        [[function_call("issue_refund", arguments, call_id="call-refund-42")]]
    )
    agent = Agent(
        name="Refund proposal agent",
        instructions="Propose refunds; application policy owns execution.",
        tools=[issue_refund],
        model=model,
    )

    result = await Runner.run(agent, "Propose the documented refund.")
    if len(result.interruptions) != 1:
        raise AssertionError("expected one SDK approval interruption")
    state = result.to_state()
    snapshot = state.to_json()
    snapshot_text = json.dumps(snapshot, sort_keys=True)
    restored = await RunState.from_json(agent, snapshot)
    interruptions = restored.get_interruptions()
    if len(interruptions) != 1:
        raise AssertionError("interruption did not survive RunState round-trip")
    interruption = interruptions[0]
    restored_arguments = json.loads(interruption.arguments or "{}")

    plane, requester, approver, _, _ = lab.build_scenario()
    proposal = _proposal(restored_arguments)
    submitted = plane.submit(requester, proposal, now=lab.NOW)
    reviewed = plane.decide(
        approver,
        submitted.review_id,
        lab.ReviewChoice.APPROVE,
        rationale_code="sdk-review-complete",
        expected_version=submitted.version,
        now=lab.NOW,
    )
    outcome = plane.execute(
        requester,
        submitted.review_id,
        reviewed.grant_id,
        proposal,
        lab.safe_provider,
        now=lab.NOW,
    )

    schema = issue_refund.params_json_schema
    return {
        "sdk_version": version("openai-agents"),
        "tool_name": interruption.name,
        "call_id": interruption.raw_item.call_id,
        "strict_schema": schema.get("additionalProperties") is False,
        "schema_properties": sorted(schema["properties"]),
        "snapshot_contains_pending_call": "call-refund-42" in snapshot_text,
        "snapshot_contains_arguments": "sdk-refund:42:1" in snapshot_text,
        "server_snapshot_required": True,
        "course_review_status": reviewed.reason,
        "course_outcome": outcome.reason,
        "effect_applied": outcome.effect_applied,
        "sdk_tool_executions": tuple(TOOL_EXECUTIONS),
        "receipt_phases": tuple(receipt.phase for receipt in plane.receipts),
    }


def demo() -> None:
    proof = asyncio.run(run_sdk_demo())
    assert proof["tool_name"] == "issue_refund"
    assert proof["strict_schema"]
    assert proof["snapshot_contains_pending_call"]
    assert proof["snapshot_contains_arguments"]
    assert proof["course_review_status"] == "review-approved"
    assert proof["course_outcome"] == "effect-completed"
    assert proof["effect_applied"]
    assert proof["sdk_tool_executions"] == ()
    assert proof["receipt_phases"] == (
        "submission", "review", "execution", "outcome"
    )
    print("OpenAI Agents SDK HITL adapter passed")


if __name__ == "__main__":
    demo()
