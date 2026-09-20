"""Credential-free contract checks for the OpenAI Agents SDK companion."""
import asyncio
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
PATH = ROOT / "curriculum/advanced/02-multi-agent-security/02_multi_agent_security_sdk.py"
SPEC = importlib.util.spec_from_file_location("advanced_02_sdk", PATH)
assert SPEC and SPEC.loader
sdk = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sdk
SPEC.loader.exec_module(sdk)


def test_sdk_handoff_uses_typed_metadata_and_no_network_call():
    handoff_object, context = asyncio.run(sdk.credential_free_demo())
    assert handoff_object.tool_name == "delegate_to_researcher"
    assert handoff_object.agent_name == "researcher"
    assert handoff_object.input_json_schema["additionalProperties"] is False
    assert context.last_decision and context.last_decision.reason == "issued"


def test_sdk_callback_fails_closed_when_server_owned_request_is_widened():
    now = sdk.datetime(2026, 9, 20, tzinfo=sdk.timezone.utc)
    service, _, authority, parent, _, request = sdk.core.build_scenario(now=now)
    context = sdk.FrameworkContext(
        service,
        authority,
        parent,
        replace(request, scopes=frozenset({"delete"})),
        now,
    )
    wrapper = sdk.RunContextWrapper(context=context)
    with pytest.raises(PermissionError, match="scope"):
        sdk.authorize_handoff(wrapper, sdk.HandoffNote(reason="Please delegate"))
    assert context.last_decision and not context.last_decision.allowed


def test_model_handoff_note_cannot_choose_identity_scope_or_resource():
    schema = sdk.HandoffNote.model_json_schema()
    assert set(schema["properties"]) == {"reason"}
    with pytest.raises(Exception):
        sdk.HandoffNote(reason="x", tenant="south", scopes=["delete"])
