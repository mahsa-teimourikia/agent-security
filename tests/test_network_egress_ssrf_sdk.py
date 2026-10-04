"""OpenAI Agents SDK and HTTPX boundary tests for Intermediate 06."""
import asyncio
import importlib.util
import json
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "06-network-egress-ssrf-and-external-resource-security"
SPEC = importlib.util.spec_from_file_location("intermediate_06_egress_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_sdk_tool_schema_exposes_only_the_untrusted_url() -> None:
    schema = SDK.fetch_external_resource.params_json_schema
    assert set(schema["properties"]) == {"url"}
    assert schema["required"] == ["url"]
    assert schema["additionalProperties"] is False
    assert SDK.fetch_external_resource.strict_json_schema is True


def test_agent_registers_one_strict_egress_boundary_tool() -> None:
    agent = SDK.build_agent()
    assert [tool.name for tool in agent.tools] == ["fetch_external_resource"]


def test_demo_uses_real_tool_invocation_and_preserves_denials() -> None:
    proof = SDK.sdk_boundary_demo()
    assert proof["safe_terminal_state"] == "allow"
    assert proof["blocked_host_terminal_state"] == "deny"
    assert proof["private_address_terminal_state"] == "deny"
    assert proof["real_tool_invocation_state"] == "allow"
    assert proof["external_content_remains_untrusted"]
    assert proof["trusted_fields_absent_from_schema"]
    assert proof["internal_authority_absent_from_results"]


def test_result_excludes_grant_peer_addresses_and_credential_binding() -> None:
    payload = json.loads(
        SDK.dispatch_fetch(
            SDK.build_runtime(), "https://research.example.test/docs/guide"
        )
    )
    assert payload["terminal_state"] == "allow"
    assert payload["trust_label"] == "external-untrusted"
    assert not {
        "grant_id", "peer_address", "approved_addresses", "attestation_id",
        "key_thumbprint",
    } & set(payload)


def test_httpx_profile_proves_no_network_and_explicit_client_controls() -> None:
    evidence = SDK.httpx_control_evidence()
    assert evidence["httpx_version"].startswith("0.28.")
    assert evidence["follow_redirects"] is False
    assert evidence["trust_env"] is False
    assert evidence["timeouts"] == {
        "connect": 0.5, "read": 0.5, "write": 0.5, "pool": 0.5,
    }
    assert evidence["max_connections"] == 8
    assert evidence["max_keepalive_connections"] == 0
    assert evidence["credential_headers_absent"] is True
    assert evidence["network_requests"] == 0


@pytest.mark.parametrize("url", ["", "x" * 2_049, None, 7])
def test_url_input_is_typed_and_bounded(url: object) -> None:
    with pytest.raises(ValueError, match="1-2048"):
        SDK.dispatch_fetch(SDK.build_runtime(), url)  # type: ignore[arg-type]


def test_denial_is_terminal_and_releases_no_content() -> None:
    payload = json.loads(
        SDK.dispatch_fetch(SDK.build_runtime(), "https://evil.example.test/admin")
    )
    assert payload["terminal_state"] == "deny"
    assert payload["content"] is None
    assert payload["content_digest"] is None


def test_async_demo_runs_in_a_notebook_event_loop() -> None:
    proof = asyncio.run(SDK.sdk_boundary_demo_async())
    assert proof["real_tool_invocation_state"] == "allow"
