"""OpenAI Agents SDK boundary tests for Intermediate 05."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "05-filesystem-code-execution-and-sandbox-security"
SPEC = importlib.util.spec_from_file_location("intermediate_05_sandbox_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_sdk_tool_schema_exposes_only_untrusted_identifiers() -> None:
    schema = SDK.analyze_uploaded_archive.params_json_schema
    assert set(schema["properties"]) == {"archive_id", "program_id"}
    assert schema["required"] == ["archive_id", "program_id"]
    assert schema["additionalProperties"] is False
    assert SDK.analyze_uploaded_archive.strict_json_schema is True


def test_agent_registers_one_strict_sandbox_boundary_tool() -> None:
    agent = SDK.build_agent()
    assert [tool.name for tool in agent.tools] == ["analyze_uploaded_archive"]


def test_demo_uses_real_tool_invocation_and_preserves_denials() -> None:
    proof = SDK.sdk_boundary_demo()
    assert proof["safe_terminal_state"] == "allow"
    assert proof["network_terminal_state"] == "deny"
    assert proof["cross_tenant_terminal_state"] == "deny"
    assert proof["real_tool_invocation_state"] == "allow"
    assert proof["trusted_fields_absent_from_schema"]
    assert proof["internal_handles_absent_from_results"]


def test_results_exclude_internal_grant_and_sandbox_handles() -> None:
    payload = json.loads(
        SDK.dispatch_analysis(
            SDK.build_runtime(), "archive:north:safe", "program:safe"
        )
    )
    assert payload["terminal_state"] == "allow"
    assert "grant_id" not in payload
    assert "sandbox_id" not in payload


def test_network_attempt_is_terminal_deny_without_report() -> None:
    payload = json.loads(
        SDK.dispatch_analysis(
            SDK.build_runtime(), "archive:north:safe", "program:network"
        )
    )
    assert payload["terminal_state"] == "deny"
    assert payload["reason"] == "sandbox-network-denied"
    assert payload["report"] is None


@pytest.mark.parametrize(
    ("archive_id", "program_id"),
    [("", "program:safe"), ("archive:north:safe", ""), ("x" * 121, "program:safe")],
)
def test_identifiers_are_bounded(archive_id: str, program_id: str) -> None:
    with pytest.raises(ValueError, match="1-120"):
        SDK.dispatch_analysis(SDK.build_runtime(), archive_id, program_id)


def test_async_demo_runs_in_notebook_event_loop() -> None:
    proof = asyncio.run(SDK.sdk_boundary_demo_async())
    assert proof["real_tool_invocation_state"] == "allow"
