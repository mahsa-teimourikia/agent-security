"""Focused tests for the Beginner 01 Agents SDK and Pydantic adapter."""

import importlib
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from agents import FunctionTool
from pydantic import ValidationError


MODULE_DIR = (
    Path(__file__).resolve().parents[1]
    / "curriculum"
    / "beginner"
    / "01-tool-policy"
)
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

core = importlib.import_module("01_tool_policy")
sdk = importlib.import_module("01_tool_policy_sdk")

NOW = datetime(2026, 9, 13, 12, 0, tzinfo=timezone.utc)


def runtime_for(amount: float = 250.0):
    actor = core.make_actor("emp-42", run_id="sdk-test-run")
    proposal = core.ActionProposal(
        "submit_claim", "claim-501", {"amount": amount},
    )
    store = core.ApprovalStore()
    approval = store.issue(actor, proposal, now=NOW)
    runtime = sdk.ExpenseRuntime(
        actor=actor,
        engine=core.PolicyEngine(approval_store=store),
        approval=approval,
        now=NOW,
    )
    return runtime


def test_sdk_registers_a_strict_approval_gated_function_tool() -> None:
    tool = sdk.submit_expense_claim

    assert isinstance(tool, FunctionTool)
    assert tool.name == "submit_expense_claim"
    assert tool.needs_approval is True
    assert tool.params_json_schema["additionalProperties"] is False
    assert set(tool.params_json_schema["required"]) == {"claim_id", "amount"}
    assert sdk.build_agent().tools == [tool]


@pytest.mark.parametrize(
    "payload",
    [
        {"claim_id": "../../etc/passwd", "amount": 250.0},
        {"claim_id": "claim-501", "amount": "250.0"},
        {"claim_id": "claim-501", "amount": True},
        {"claim_id": "claim-501", "amount": 0.0},
        {"claim_id": "claim-501", "amount": 250.0, "tenant": "globex"},
    ],
)
def test_pydantic_boundary_rejects_malformed_or_authority_fields(payload) -> None:
    with pytest.raises(ValidationError):
        sdk.SubmitClaimInput.model_validate(payload, strict=True)


def test_sdk_payload_cannot_change_an_approved_amount() -> None:
    receipt = sdk.dispatch_json(
        runtime_for(250.0),
        '{"claim_id":"claim-501","amount":251.0}',
    )

    assert receipt.decision == "deny"
    assert receipt.reason == "approval_proposal_mismatch"
    assert not receipt.executed


def test_exact_approved_sdk_payload_executes_with_safe_evidence() -> None:
    receipt = sdk.dispatch_json(
        runtime_for(250.0),
        '{"claim_id":"claim-501","amount":250.0}',
    )

    assert receipt.decision == "allow"
    assert receipt.executed
    assert len(receipt.proposal_digest) == 64
    assert receipt.policy_version == core.POLICY_VERSION
    assert receipt.correlation_id == "sdk-test-run"
    assert "amount" not in receipt.model_dump()
