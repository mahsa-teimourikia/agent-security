"""Real OpenAI Agents SDK boundary tests for Intermediate 04."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "04-secrets-and-credential-security"
SPEC = importlib.util.spec_from_file_location("intermediate_04_credentials_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_sdk_tool_schema_exposes_only_resource_selection() -> None:
    schema = SDK.read_policy_record.params_json_schema
    assert schema["required"] == ["policy_id"]
    assert set(schema["properties"]) == {"policy_id"}
    assert schema["additionalProperties"] is False
    assert SDK.read_policy_record.strict_json_schema is True


def test_agent_registers_one_strict_credential_safe_tool() -> None:
    agent = SDK.build_agent()
    assert [tool.name for tool in agent.tools] == ["read_policy_record"]


def test_credential_free_demo_uses_real_tool_invocation_without_material() -> None:
    proof = SDK.credential_free_demo()
    assert proof["direct_terminal_state"] == "allow"
    assert proof["real_tool_invocation_state"] == "allow"
    assert proof["denied_terminal_state"] == "deny"
    assert proof["denied_content_absent"]
    assert proof["trusted_fields_absent_from_schema"]
    assert proof["lease_ids_absent_from_results"]
    assert proof["raw_material_absent"]


def test_runtime_context_supplies_identity_and_application_boundary() -> None:
    payload = json.loads(SDK.dispatch_policy(SDK.build_runtime(), "policy:north:7"))
    assert payload["terminal_state"] == "allow"
    assert "lease_id" not in payload
    assert len(payload["trace_ids"]) == 2


def test_cross_tenant_resource_is_denied_without_disclosure() -> None:
    payload = json.loads(SDK.dispatch_policy(SDK.build_runtime(), "policy:south:9"))
    assert payload["terminal_state"] == "deny"
    assert payload["content"] is None


@pytest.mark.parametrize("policy_id", ["", "x" * 121])
def test_policy_identifier_is_bounded(policy_id: str) -> None:
    with pytest.raises(ValueError, match="1-120"):
        SDK.dispatch_policy(SDK.build_runtime(), policy_id)


def test_async_demo_can_run_in_notebook_event_loop() -> None:
    proof = asyncio.run(SDK.credential_free_demo_async())
    assert proof["real_tool_invocation_state"] == "allow"
