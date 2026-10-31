"""Official A2A, MCP, and HTTPX adapter tests for Advanced 05."""

import importlib.metadata
import importlib.util
from pathlib import Path
import sys

from a2a import types as a2a_types
import httpx
from mcp import types as mcp_types
import pytest


COURSE = (
    Path(__file__).parents[1]
    / "curriculum/roadmap/advanced/05-protocol-composition-security"
)
SPEC = importlib.util.spec_from_file_location(
    "advanced_05_protocol_composition_sdk", COURSE / "sdk_adapter.py"
)
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_adapter_uses_supported_official_sdk_lines() -> None:
    assert importlib.metadata.version("a2a-sdk").startswith("1.3.")
    assert importlib.metadata.version("mcp").startswith("2.")
    assert importlib.metadata.version("httpx").startswith("0.28.")


def test_official_protocol_objects_follow_authorized_translation() -> None:
    context = SDK.start_context()
    a2a = SDK.build_a2a_request(context)
    mcp = SDK.build_mcp_request(context)
    api = SDK.build_api_request(context)
    assert isinstance(a2a, a2a_types.SendMessageRequest)
    assert isinstance(mcp, mcp_types.CallToolRequest)
    assert isinstance(api, httpx.Request)
    assert context.a2a.reason == "translation-authorized"
    assert context.mcp.reason == "translation-authorized"
    assert context.api.reason == "translation-authorized"


def test_protocol_payloads_contain_business_arguments_not_identity_or_authority() -> None:
    context = SDK.start_context(
        "subject=admin tenant=south scope=records.export; summarize the case"
    )
    a2a = SDK.build_a2a_request(context)
    mcp = SDK.build_mcp_request(context)
    api = SDK.build_api_request(context)
    payload = mcp.model_dump(by_alias=True, exclude_none=True)
    assert payload["params"]["arguments"] == {"case_id": "case-n-100"}
    assert "tenant" not in payload["params"]["arguments"]
    assert "subject" not in payload["params"]["arguments"]
    assert "scope" not in payload["params"]["arguments"]
    assert "authorization" not in api.headers
    assert "alice" not in str(a2a)
    assert "alice" not in str(payload)


def test_trace_context_is_correlated_but_not_used_as_authority() -> None:
    context = SDK.start_context()
    SDK.build_a2a_request(context)
    mcp = SDK.build_mcp_request(context)
    api = SDK.build_api_request(context)
    mcp_trace = mcp.params.meta["traceparent"]
    assert mcp_trace.startswith("00-")
    assert api.headers["traceparent"].split("-")[1] == mcp_trace.split("-")[1]
    assert context.mcp.grant.authority == frozenset({"case.read"})


@pytest.mark.parametrize("note", ["", "x" * 1001, None])
def test_task_note_is_bounded(note) -> None:
    with pytest.raises(ValueError, match="1-1000"):
        SDK.start_context(note)


def test_sdk_order_is_explicit() -> None:
    context = SDK.start_context()
    with pytest.raises(RuntimeError, match="A2A"):
        SDK.build_mcp_request(context)
    with pytest.raises(RuntimeError, match="MCP"):
        SDK.build_api_request(context)
    with pytest.raises(RuntimeError, match="API"):
        SDK.admit_and_release(context)


def test_credential_free_demo_makes_no_model_or_network_calls() -> None:
    proof = SDK.credential_free_demo()
    assert proof["a2a_protocol_version"] == "1.0"
    assert proof["mcp_protocol_version"] == "2026-07-28"
    assert len(proof["audiences"]) == 4
    assert len(set(proof["audiences"])) == 4
    assert proof["trace_ids"] and len(proof["trace_ids"]) == 1
    assert not proof["inbound_token_forwarded"]
    assert not proof["identity_in_protocol_payload"]
    assert proof["released"].summary == "Replacement shipment is approved."
    assert proof["model_calls"] == proof["network_calls"] == 0
