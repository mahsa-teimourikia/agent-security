"""Credential-free real-SDK tests for Foundation 05."""
import asyncio
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "05-authorization-approval-and-least-privilege"
SPEC = importlib.util.spec_from_file_location("foundation_05_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)
NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


def test_real_sdk_hook_pauses_then_same_pep_executes() -> None:
    result, evidence = asyncio.run(SDK.credential_free_demo(now=NOW))
    assert result.successful and result.effect_applied
    assert evidence["tool_name"] == "issue_approved_refund"
    assert evidence["strict_json_schema"] is True
    assert evidence["needs_approval_is_callable"] is True
    assert evidence["paused"] is True
    assert evidence["pdp_status"] == "pause"
    assert evidence["input_schema"]["additionalProperties"] is False
    assert evidence["output_schema"]["additionalProperties"] is False


def test_sdk_schema_excludes_identity_and_approval_authority() -> None:
    properties = SDK.issue_approved_refund.params_json_schema["properties"]
    assert set(properties) == {
        "resource_id",
        "amount_cents",
        "currency",
        "purpose",
        "logical_operation_id",
    }
    assert not ({"subject", "tenant", "role", "scope", "approval_id", "is_admin"} & set(properties))


@pytest.mark.parametrize(
    "payload",
    [
        {"resource_id": "case:north:42", "amount_cents": True, "currency": "CAD", "purpose": "customer-remediation", "logical_operation_id": "sdk:bad:1"},
        {"resource_id": "case:north:42", "amount_cents": 500, "currency": "USD", "purpose": "customer-remediation", "logical_operation_id": "sdk:bad:2"},
        {"resource_id": "case:north:42", "amount_cents": 500, "currency": "CAD", "purpose": "customer-remediation", "logical_operation_id": "sdk:bad:3", "is_admin": True},
    ],
)
def test_sdk_contract_rejects_coercion_enums_and_authority_fields(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SDK.RefundInput.model_validate(payload, strict=True)
