"""Credential-free SDK contract tests for Foundation 04."""
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "04-secure-tool-and-action-interface-design"
SPEC = importlib.util.spec_from_file_location("foundation_04_sdk", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SDK
SPEC.loader.exec_module(SDK)
NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


def test_sdk_publishes_strict_bounded_input_and_output_contracts() -> None:
    tool = SDK.issue_approved_refund
    model = tool.params_json_schema["$defs"]["IssueApprovedRefundInput"]
    assert tool.strict_json_schema is True and tool.needs_approval is True
    assert tool.timeout_seconds == 2.0
    assert tool.params_json_schema["additionalProperties"] is False
    assert model["additionalProperties"] is False
    assert set(model["required"]) == {"case_id", "amount_cents", "currency"}
    assert tool.output_json_schema["additionalProperties"] is False


@pytest.mark.parametrize("payload", [
    {"case_id": "case:north:42", "amount_cents": "500", "currency": "CAD"},
    {"case_id": "case:north:42", "amount_cents": True, "currency": "CAD"},
    {"case_id": "case:north:42", "amount_cents": 500, "currency": "USD"},
    {"case_id": "case:north:42", "amount_cents": 500, "currency": "CAD", "subject": "admin"},
])
def test_pydantic_contract_rejects_coercion_wrong_enum_and_authority_fields(payload) -> None:
    with pytest.raises(ValidationError):
        SDK.IssueApprovedRefundInput.model_validate(payload, strict=True)


def test_sdk_shaped_payload_enters_same_application_gateway() -> None:
    decision, evidence = SDK.credential_free_demo(now=NOW)
    assert decision.effect_applied and decision.reason == "contract-allow"
    assert evidence["tool_name"] == "issue_approved_refund"
    fields = set(evidence["input_schema"]["$defs"]["IssueApprovedRefundInput"]["properties"])
    assert fields == {"case_id", "amount_cents", "currency"}
