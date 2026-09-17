"""Security contract tests for the Intermediate 01 Agents SDK companion."""

import importlib
import json
import sys
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).parent.parent / "curriculum" / "intermediate" / "01-identity-propagation"
sys.path.insert(0, str(MODULE_PATH.resolve()))
sdk = importlib.import_module("01_identity_propagation_sdk")


def test_tool_schema_exposes_only_resource_selection() -> None:
    schema = sdk.read_authorized_document.params_json_schema
    assert schema["required"] == ["document_id"]
    assert set(schema["properties"]) == {"document_id"}
    assert schema["additionalProperties"] is False


def test_agent_registers_one_strict_read_tool() -> None:
    assert [tool.name for tool in sdk.SDK_AGENT.tools] == ["read_authorized_document"]
    assert sdk.read_authorized_document.strict_json_schema is True


def test_runtime_allows_owned_document_and_issues_request_id() -> None:
    runtime = sdk.build_runtime("alice")
    payload = json.loads(sdk.dispatch_authorized_read(runtime, "doc-101"))
    assert payload["terminal_state"] == "answered"
    assert payload["correlation_id"].startswith("request-")


def test_runtime_blocks_unowned_document_without_disclosure() -> None:
    runtime = sdk.build_runtime("alice")
    payload = json.loads(sdk.dispatch_authorized_read(runtime, "doc-secret"))
    assert payload["terminal_state"] == "blocked"
    assert "acquisition" not in payload["answer"].lower()


def test_unknown_subject_cannot_construct_runtime() -> None:
    with pytest.raises(PermissionError, match="unknown subject"):
        sdk.build_runtime("unknown")


@pytest.mark.parametrize("document_id", ["", "x" * 101])
def test_document_identifier_is_bounded(document_id: str) -> None:
    with pytest.raises(ValueError, match="1-100"):
        sdk.dispatch_authorized_read(sdk.build_runtime("alice"), document_id)
