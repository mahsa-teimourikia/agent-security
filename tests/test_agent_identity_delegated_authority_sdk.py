"""Real OpenAI Agents SDK boundary tests for Intermediate 03."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "03-agent-identity-and-delegated-authority"
SPEC = importlib.util.spec_from_file_location("intermediate_03_identity_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_sdk_tool_schema_exposes_only_resource_selection() -> None:
    schema = SDK.read_case_attachment.params_json_schema
    assert schema["required"] == ["attachment_id"]
    assert set(schema["properties"]) == {"attachment_id"}
    assert schema["additionalProperties"] is False
    assert SDK.read_case_attachment.strict_json_schema is True


def test_agent_registers_one_strict_delegated_tool() -> None:
    agent = SDK.build_agent()
    assert [tool.name for tool in agent.tools] == ["read_case_attachment"]


def test_credential_free_demo_uses_real_tool_invocation_and_no_credentials() -> None:
    proof = SDK.credential_free_demo()
    assert proof["direct_terminal_state"] == "allow"
    assert proof["real_tool_invocation_state"] == "allow"
    assert proof["denied_terminal_state"] == "deny"
    assert proof["denied_content_absent"]
    assert proof["identity_fields_absent_from_schema"]
    assert proof["credential_markers_absent"]


def test_runtime_context_not_model_arguments_supplies_identity_chain() -> None:
    runtime = SDK.build_runtime()
    payload = json.loads(SDK.dispatch_attachment(runtime, "attachment:north:7"))
    assert payload["terminal_state"] == "allow"
    assert len(payload["grant_ids"]) == 2
    assert len(payload["trace_ids"]) == 4


def test_cross_tenant_resource_is_denied_without_disclosure() -> None:
    runtime = SDK.build_runtime()
    payload = json.loads(SDK.dispatch_attachment(runtime, "attachment:south:9"))
    assert payload["terminal_state"] == "deny"
    assert payload["content"] is None


@pytest.mark.parametrize("attachment_id", ["", "x" * 121])
def test_attachment_identifier_is_bounded(attachment_id: str) -> None:
    with pytest.raises(ValueError, match="1-120"):
        SDK.dispatch_attachment(SDK.build_runtime(), attachment_id)


def test_async_demo_can_run_in_notebook_event_loop() -> None:
    proof = asyncio.run(SDK.credential_free_demo_async())
    assert proof["real_tool_invocation_state"] == "allow"
