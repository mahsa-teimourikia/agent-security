"""OpenAI Agents SDK and Pydantic mapping for Foundation 04.

This module makes no model or network call. It proves that the pinned SDK can
publish a strict input/output schema and request a workflow pause while the
application-owned gateway remains the execution authority.
"""
from __future__ import annotations

from datetime import datetime
import importlib.util
from pathlib import Path
import sys
from typing import Literal

from agents import function_tool
from pydantic import BaseModel, ConfigDict, Field


COURSE = Path(__file__).parent
SPEC = importlib.util.spec_from_file_location("foundation_04_tool_lab", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


class IssueApprovedRefundInput(BaseModel):
    """Strict model-visible fields; identity and grants are deliberately absent."""

    model_config = ConfigDict(extra="forbid", strict=True)
    case_id: str = Field(pattern=r"^case:[a-z][a-z0-9-]{1,15}:[1-9][0-9]{0,8}$")
    amount_cents: int = Field(ge=1, le=50_000)
    currency: Literal["CAD"]


class RefundReceiptOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    receipt_id: str
    case_id: str
    amount_cents: int
    currency: Literal["CAD"]
    provider_status: Literal["confirmed"]


@function_tool(
    name_override="issue_approved_refund",
    description_override=(
        "Request one refund for an active support case. The application independently "
        "validates identity, tenant, case state, authorization, and idempotency."
    ),
    strict_mode=True,
    needs_approval=True,
    timeout=2.0,
    output_type=RefundReceiptOutput,
)
async def issue_approved_refund(arguments: IssueApprovedRefundInput) -> RefundReceiptOutput:
    """Schema surface only; a production runner must route through ToolGateway."""

    raise RuntimeError("bind the SDK callback to the application-owned ToolGateway")


def dispatch_with_sdk_contract(
    gateway: object,
    actor: object,
    payload: dict[str, object],
    *,
    operation_id: str,
    grant_id: str,
    now: datetime,
) -> object:
    """Validate the SDK-shaped payload, then enter the trusted gateway."""

    validated = IssueApprovedRefundInput.model_validate(payload, strict=True)
    proposal = LAB.ToolProposal(
        issue_approved_refund.name,
        "1.0.0",
        validated.model_dump(),
        operation_id,
    )
    return gateway.dispatch(actor, proposal, grant_id=grant_id, now=now)


def credential_free_demo(*, now: datetime) -> tuple[object, dict[str, object]]:
    gateway, actor = LAB.build_gateway()
    payload = {"case_id": "case:north:42", "amount_cents": 2_500, "currency": "CAD"}
    parsed = IssueApprovedRefundInput.model_validate(payload, strict=True)
    proposal = LAB.ToolProposal(issue_approved_refund.name, "1.0.0", parsed.model_dump(), "sdk:refund:1")
    grant = LAB.issue_demo_grant(proposal, actor, grant_id="grant:sdk:1", now=now)
    gateway.register_grant(grant)
    decision = dispatch_with_sdk_contract(
        gateway,
        actor,
        payload,
        operation_id=proposal.logical_operation_id,
        grant_id=grant.grant_id,
        now=now,
    )
    evidence = {
        "tool_name": issue_approved_refund.name,
        "strict_json_schema": issue_approved_refund.strict_json_schema,
        "needs_approval": issue_approved_refund.needs_approval,
        "timeout_seconds": issue_approved_refund.timeout_seconds,
        "input_schema": issue_approved_refund.params_json_schema,
        "output_schema": issue_approved_refund.output_json_schema,
    }
    return decision, evidence
