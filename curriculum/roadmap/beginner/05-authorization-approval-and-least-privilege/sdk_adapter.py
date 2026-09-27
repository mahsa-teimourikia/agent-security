"""OpenAI Agents SDK approval-hook mapping for Foundation 05.

This credential-free adapter makes no model or network call. It demonstrates
that a real SDK can pause a workflow for high-risk arguments while the same
application-owned PDP and PEP remain the authorization and execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import importlib.util
from pathlib import Path
import sys
from typing import Annotated, Literal

from agents import RunContextWrapper, function_tool
from pydantic import BaseModel, ConfigDict, Field


COURSE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("foundation_05_authorization_lab", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


class RefundInput(BaseModel):
    """Only proposed business fields are model visible."""

    model_config = ConfigDict(extra="forbid", strict=True)
    resource_id: str = Field(pattern=r"^case:[a-z][a-z0-9-]{1,15}:[1-9][0-9]{0,8}$")
    amount_cents: int = Field(ge=1, le=10_000)
    currency: Literal["CAD"]
    purpose: Literal["customer-remediation"]
    logical_operation_id: str = Field(min_length=6, max_length=80)


class RefundOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    receipt_id: str
    resource_id: str
    amount_cents: int
    currency: Literal["CAD"]


@dataclass
class SDKContext:
    actor: object
    pdp: object
    last_decision: object | None = None


def proposal_from_input(arguments: RefundInput) -> object:
    return LAB.ActionProposal(
        "issue_approved_refund",
        arguments.resource_id,
        arguments.amount_cents,
        arguments.currency,
        arguments.purpose,
        arguments.logical_operation_id,
    )


async def approval_hook(
    context: RunContextWrapper[SDKContext],
    raw_arguments: dict[str, object],
    _call_id: str,
) -> bool:
    """Pause every request that is not already an application ALLOW."""

    parsed = RefundInput.model_validate(raw_arguments, strict=True)
    decision = context.context.pdp.evaluate(context.context.actor, proposal_from_input(parsed))
    context.context.last_decision = decision
    return decision.status is not LAB.DecisionStatus.ALLOW


@function_tool(
    name_override="issue_approved_refund",
    description_override=(
        "Propose one refund. The application independently resolves identity, "
        "authorization, current resource state, approval, and final execution."
    ),
    strict_mode=True,
    needs_approval=approval_hook,
    timeout=2.0,
    output_type=RefundOutput,
)
async def issue_approved_refund(
    resource_id: Annotated[
        str, Field(pattern=r"^case:[a-z][a-z0-9-]{1,15}:[1-9][0-9]{0,8}$")
    ],
    amount_cents: Annotated[int, Field(ge=1, le=10_000)],
    currency: Literal["CAD"],
    purpose: Literal["customer-remediation"],
    logical_operation_id: Annotated[str, Field(min_length=6, max_length=80)],
) -> RefundOutput:
    """Schema surface only; direct wrapper calls are not an execution path."""

    raise RuntimeError("route approved runs through the application-owned PEP")


def dispatch_with_sdk_contract(
    pep: object,
    actor: object,
    payload: dict[str, object],
    *,
    approval_id: str,
    now: datetime,
) -> object:
    """Validate SDK arguments, then reauthorize through the same trusted PEP."""

    parsed = RefundInput.model_validate(payload, strict=True)
    return pep.enforce(
        actor,
        proposal_from_input(parsed),
        approval_id=approval_id,
        now=now,
    )


async def credential_free_demo(*, now: datetime) -> tuple[object, dict[str, object]]:
    pep, actor, approver, _ = LAB.build_scenario()
    payload: dict[str, object] = {
        "resource_id": "case:north:42",
        "amount_cents": 2_500,
        "currency": "CAD",
        "purpose": "customer-remediation",
        "logical_operation_id": "sdk:refund:1",
    }
    context = SDKContext(actor, pep.pdp)
    paused = await approval_hook(RunContextWrapper(context), payload, "call:sdk:1")
    assert paused and context.last_decision.status is LAB.DecisionStatus.PAUSE
    parsed = RefundInput.model_validate(payload, strict=True)
    proposal = proposal_from_input(parsed)
    receipt = LAB.authorize_and_approve(
        pep,
        actor,
        approver,
        proposal,
        approval_id="approval:sdk:1",
        now=now,
    )
    result = dispatch_with_sdk_contract(
        pep,
        actor,
        payload,
        approval_id=receipt.approval_id,
        now=now,
    )
    evidence = {
        "tool_name": issue_approved_refund.name,
        "strict_json_schema": issue_approved_refund.strict_json_schema,
        "needs_approval_is_callable": callable(issue_approved_refund.needs_approval),
        "paused": paused,
        "pdp_status": context.last_decision.status.value,
        "input_schema": issue_approved_refund.params_json_schema,
        "output_schema": issue_approved_refund.output_json_schema,
    }
    return result, evidence
