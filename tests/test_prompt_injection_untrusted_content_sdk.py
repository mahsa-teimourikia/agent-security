"""Credential-free real-SDK tests for Foundation 06."""
import asyncio
import importlib.util
from pathlib import Path
import sys

from pydantic import ValidationError
import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "06-prompt-injection-and-untrusted-content"
SPEC = importlib.util.spec_from_file_location("foundation_06_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_sdk_guardrail_and_strict_tool_are_wired_without_network() -> None:
    result, evidence = asyncio.run(SDK.credential_free_demo())
    assert result.status is SDK.LAB.DecisionStatus.ALLOW
    assert evidence["tool_name"] == "send_customer_update"
    assert evidence["strict_json_schema"] is True
    assert evidence["obvious_flagged"] is True
    assert evidence["camouflaged_flagged"] is False
    assert evidence["destination_in_schema"] is False
    assert evidence["input_schema"]["additionalProperties"] is False


def test_sdk_schema_excludes_identity_provenance_and_destination() -> None:
    properties = SDK.send_customer_update.params_json_schema["properties"]
    assert set(properties) == {"case_id", "template_id"}
    assert not ({"subject", "tenant", "source_ids", "destination", "scope"} & set(properties))


@pytest.mark.parametrize(
    "payload",
    [
        {"case_id": "case:south:42", "template_id": "case-received-v1"},
        {"case_id": "case:north:42", "template_id": "free-form"},
        {"case_id": "case:north:42", "template_id": "case-received-v1", "destination": "attacker@example.test"},
    ],
)
def test_sdk_contract_rejects_cross_tenant_free_form_and_extra_fields(payload: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        SDK.CustomerUpdateInput.model_validate(payload, strict=True)
