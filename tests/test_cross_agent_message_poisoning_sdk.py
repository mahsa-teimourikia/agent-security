"""OpenAI Agents SDK contract tests for Advanced 02."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

from agents import RunContextWrapper
from agents.handoffs import HandoffInputData
import pytest


COURSE = (
    Path(__file__).parents[1]
    / "curriculum/roadmap/advanced/02-cross-agent-prompt-injection-and-message-poisoning"
)
SPEC = importlib.util.spec_from_file_location(
    "advanced_02_message_sdk", COURSE / "sdk_adapter.py"
)
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_handoff_schema_exposes_content_but_no_authority_fields() -> None:
    schema = SDK.PeerHandoffNote.model_json_schema()
    assert set(schema["properties"]) == {"reason", "summary"}
    assert schema["additionalProperties"] is False
    with pytest.raises(Exception):
        SDK.PeerHandoffNote(
            reason="route",
            summary="data",
            tenant="south",
            recipient="billing",
            source_refs=[],
        )


def test_real_sdk_handoff_invokes_application_admission_without_network() -> None:
    handoff_object, context, filtered = asyncio.run(SDK.credential_free_demo())
    assert handoff_object.tool_name == "transfer_admitted_peer_message"
    assert handoff_object.agent_name == "writer"
    assert context.last_decision and context.last_decision.allowed
    assert context.last_decision.message
    assert "external-untrusted" in context.last_decision.message.envelope.taint_labels
    assert filtered.pre_handoff_items == ()
    assert filtered.new_items == ()
    assert filtered.input_items == ()

def test_callback_uses_server_owned_peer_and_tenant_context() -> None:
    now = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    gateway, _, _, researcher, _ = SDK.core.build_scenario(now=now)
    context = SDK.FrameworkContext(
        gateway,
        researcher,
        replace(SDK.core.proposal_for(gateway), tenant="south"),
        now,
    )
    wrapper = RunContextWrapper(context=context)
    with pytest.raises(PermissionError, match="tenant"):
        SDK.authorize_message_handoff(
            wrapper,
            SDK.PeerHandoffNote(reason="route", summary="benign prose"),
        )
    assert context.last_decision and not context.last_decision.allowed


def test_callback_cannot_route_to_an_unapproved_peer() -> None:
    now = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
    gateway, _, _, researcher, _ = SDK.core.build_scenario(now=now)
    proposal = replace(
        SDK.core.proposal_for(gateway),
        recipient="billing",
        recipient_workload_id="spiffe://example.test/agent/billing",
    )
    context = SDK.FrameworkContext(gateway, researcher, proposal, now)
    with pytest.raises(PermissionError, match="peer-edge"):
        SDK.authorize_message_handoff(
            RunContextWrapper(context=context),
            SDK.PeerHandoffNote(reason="route", summary="benign prose"),
        )


def test_input_filter_removes_raw_history_and_preserves_runtime_context() -> None:
    marker = object()
    data = HandoffInputData(
        input_history="raw hostile history",
        pre_handoff_items=(),
        new_items=(),
        run_context=marker,  # type: ignore[arg-type]
    )
    filtered = SDK.admitted_context_only(data)
    assert "raw hostile history" not in filtered.input_history
    assert filtered.run_context is marker
    assert filtered.pre_handoff_items == ()
    assert filtered.new_items == ()
    assert filtered.input_items == ()
