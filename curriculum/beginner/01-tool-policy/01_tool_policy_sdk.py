"""OpenAI Agents SDK and Pydantic adapter for the tool-policy lab.

This credential-free module registers a real Agents SDK function tool and
exercises the same application-owned policy gateway used by the core lab.  It
does not call a model or the OpenAI API.  SDK schema validation and approval
interrupts are useful controls, but they do not replace authorization at the
side-effect boundary.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any

from agents import Agent, FunctionTool, RunContextWrapper
from agents.decorators import tool
from pydantic import BaseModel, ConfigDict, Field, ValidationError


core = importlib.import_module("01_tool_policy")
ActionProposal = core.ActionProposal
ActorContext = core.ActorContext
ApprovalReceipt = core.ApprovalReceipt
ApprovalStore = core.ApprovalStore
Decision = core.Decision
PolicyEngine = core.PolicyEngine
make_actor = core.make_actor


ClaimId = Annotated[
    str,
    Field(pattern=r"^claim-[0-9]+$", min_length=7, max_length=64),
]
Amount = Annotated[
    float,
    Field(strict=True, gt=0, le=5000),
]


class SubmitClaimInput(BaseModel):
    """Strict boundary model mirroring the SDK-generated function schema."""

    model_config = ConfigDict(extra="forbid", strict=True)

    claim_id: ClaimId
    amount: Amount


class ToolReceipt(BaseModel):
    """Safe, structured result returned to the agent runtime."""

    model_config = ConfigDict(extra="forbid")

    decision: str
    reason: str
    correlation_id: str
    proposal_digest: str
    policy_version: str
    executed: bool


@dataclass
class ExpenseRuntime:
    """Trusted runtime context supplied by the application, never the model."""

    actor: ActorContext
    engine: PolicyEngine
    approval: ApprovalReceipt | None
    now: datetime


def dispatch_submit_claim(
    runtime: ExpenseRuntime,
    payload: SubmitClaimInput,
) -> ToolReceipt:
    """Translate validated SDK input into the application policy contract."""
    proposal = ActionProposal(
        "submit_claim",
        payload.claim_id,
        {"amount": payload.amount},
    )
    decision = runtime.engine.evaluate(
        runtime.actor,
        proposal,
        runtime.approval,
        now=runtime.now,
    )
    event = runtime.engine.audit_log[-1]
    return ToolReceipt(
        decision=decision.state.value,
        reason=decision.reason,
        correlation_id=event.correlation_id,
        proposal_digest=event.proposal_digest,
        policy_version=event.policy_version,
        executed=event.terminal_state == "executed",
    )


def dispatch_json(runtime: ExpenseRuntime, raw_arguments: str) -> ToolReceipt:
    """Validate model-controlled JSON strictly, then call the trusted gateway."""
    payload = SubmitClaimInput.model_validate_json(raw_arguments, strict=True)
    return dispatch_submit_claim(runtime, payload)


@tool(
    name_override="submit_expense_claim",
    strict_mode=True,
    needs_approval=True,
)
async def submit_expense_claim(
    ctx: RunContextWrapper[ExpenseRuntime],
    claim_id: ClaimId,
    amount: Amount,
) -> dict[str, Any]:
    """Submit one expense claim through the application policy gateway.

    Args:
        claim_id: Canonical claim identifier owned by the authenticated tenant.
        amount: Positive reimbursement amount, capped at 5000.
    """
    payload = SubmitClaimInput(claim_id=claim_id, amount=amount)
    return dispatch_submit_claim(ctx.context, payload).model_dump()


def build_agent() -> Agent[ExpenseRuntime]:
    """Register the guarded function tool without starting a model run."""
    return Agent[ExpenseRuntime](
        name="Expense assistant",
        instructions=(
            "Propose expense actions. The application policy gateway decides "
            "whether any tool action may execute."
        ),
        tools=[submit_expense_claim],
    )


def tool_schema() -> dict[str, Any]:
    """Return the SDK-generated JSON Schema for inspection and tests."""
    assert isinstance(submit_expense_claim, FunctionTool)
    return submit_expense_claim.params_json_schema


def run_demo() -> None:
    """Exercise schema and policy controls without credentials or model calls."""
    now = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)
    actor = make_actor("emp-42", run_id="sdk-demo-run")
    approved = ActionProposal(
        "submit_claim", "claim-501", {"amount": 250.0},
    )
    store = ApprovalStore()
    approval = store.issue(actor, approved, now=now)
    runtime = ExpenseRuntime(
        actor=actor,
        engine=PolicyEngine(approval_store=store),
        approval=approval,
        now=now,
    )

    print("OpenAI Agents SDK function schema:")
    print(json.dumps(tool_schema(), indent=2, sort_keys=True))

    try:
        SubmitClaimInput.model_validate(
            {"claim_id": "claim-501", "amount": "250.0"}, strict=True,
        )
    except ValidationError:
        print("\n[PASS] Pydantic strict mode rejected a string amount.")
    else:
        raise AssertionError("strict validation unexpectedly coerced a string")

    altered = dispatch_json(
        runtime,
        json.dumps({"claim_id": "claim-501", "amount": 251.0}),
    )
    assert altered.decision == "deny"
    assert altered.reason == "approval_proposal_mismatch"
    print("[PASS] Application policy rejected arguments changed after approval.")

    allowed = dispatch_json(
        runtime,
        json.dumps({"claim_id": "claim-501", "amount": 250.0}),
    )
    assert allowed.decision == "allow" and allowed.executed
    print("[PASS] Exact approved proposal reached the simulated executor.")
    print(json.dumps(allowed.model_dump(), indent=2, sort_keys=True))

    agent = build_agent()
    assert agent.tools == [submit_expense_claim]
    print("[PASS] Function tool registered with the Agents SDK; no API call made.")


if __name__ == "__main__":
    run_demo()
