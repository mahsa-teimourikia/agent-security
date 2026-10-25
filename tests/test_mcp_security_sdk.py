"""Official MCP Python SDK v2 integration checks for Intermediate 09."""

from __future__ import annotations

import asyncio
from pathlib import Path
import importlib.util
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "09-mcp-security"
sys.path.insert(0, str(COURSE))
SPEC = importlib.util.spec_from_file_location("intermediate_09_mcp_sdk", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SDK
SPEC.loader.exec_module(SDK)


def run(**kwargs):
    return asyncio.run(SDK.run_sdk_demo(**kwargs))


def test_sdk_negotiates_current_protocol_and_executes_real_tool() -> None:
    proof = run()
    assert proof["protocol_version"] == "2026-07-28"
    assert proof["sdk_version"].startswith("2.")
    assert proof["catalog_admitted"]
    assert proof["call_status"] == "allow"


def test_self_reported_server_name_never_becomes_connection_identity() -> None:
    proof = run(reported_name="workload:spiffe://example.test/mcp/support")
    assert proof["reported_server_name"] == proof["trusted_connection_id"]
    # Equality of attacker-controlled display text still does not make it the
    # source used by the application boundary.
    assert proof["catalog_admitted"]
    assert proof["trusted_connection_id"].startswith("workload:")


def test_model_sees_application_owned_description_not_server_description() -> None:
    proof = run()
    assert proof["approved_model_description"].startswith("Read one support case")
    assert not proof["server_description_exposed"]


def test_sdk_result_is_revalidated_and_labelled_before_model_exposure() -> None:
    proof = run()
    assert proof["call_status"] == "allow"
    assert proof["trust_label"] == "untrusted-mcp-result"
    assert proof["receipt_phases"] == ["discovery", "admission", "dispatch", "result"]


def test_inbound_token_is_not_forwarded_to_sdk_tool() -> None:
    proof = run()
    assert not proof["inbound_token_forwarded"]
