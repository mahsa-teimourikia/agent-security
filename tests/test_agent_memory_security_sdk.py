"""Credential-free real-SDK tests for Intermediate 01."""
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "01-agent-memory-security"
SPEC = importlib.util.spec_from_file_location("intermediate_01_memory_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_sdk_tools_and_session_run_without_network() -> None:
    proof = SDK.credential_free_demo()
    assert proof["write"]["status"] == "created"
    assert proof["read"]["status"] == "ready"
    assert proof["session_items"] == 2
    assert proof["session_is_conversation_history_not_memory_policy"] is True
    assert proof["write_tool"]["strict_json_schema"] is True
    assert proof["read_tool"]["strict_json_schema"] is True


def test_write_tool_schema_excludes_scope_provenance_consent_and_lifecycle() -> None:
    properties = SDK.remember_confirmed_contact_preference.params_json_schema["properties"]
    assert set(properties) == {"value"}
    assert SDK.credential_free_demo()["write_tool"]["trusted_fields_excluded"] is True


def test_read_tool_has_no_model_controlled_scope_fields() -> None:
    properties = SDK.recall_contact_preference.params_json_schema["properties"]
    assert properties == {}


def test_adapter_still_routes_through_course_policy() -> None:
    service, sources = SDK.LAB.build_system()
    runtime = SDK.SDKRuntime(SDK.LAB.actor("sdk:deny", tenant="south"), service, sources)
    decision = SDK.remember(runtime, "email")
    assert (decision["status"], decision["reason"]) == ("deny", "source-scope")

