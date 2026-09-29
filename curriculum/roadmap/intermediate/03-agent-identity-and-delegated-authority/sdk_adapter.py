"""Credential-free OpenAI Agents SDK adapter for Intermediate 03.

The real SDK tool exposes only an attachment identifier. Human session,
workload attestation, agent identity, tenant, purpose, audiences, grants,
sender binding, and correlation IDs remain in trusted application context.
No model, network request, API key, or live identity provider is used.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

from agents import Agent, RunContextWrapper, function_tool
from agents.tool_context import ToolContext


SPEC = importlib.util.spec_from_file_location(
    "intermediate_03_identity_lab", Path(__file__).with_name("lab.py")
)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


@dataclass
class SDKRuntime:
    """Trusted server-owned context; never hydrate it from tool arguments."""

    application: Any
    session_id: str
    agent_attestation_id: str
    now: Any
    request_counter: int = 0

    def next_request_id(self) -> str:
        self.request_counter += 1
        return f"sdk:attachment:{self.request_counter}"


def dispatch_attachment(runtime: SDKRuntime, attachment_id: str) -> str:
    if not attachment_id or len(attachment_id) > 120:
        raise ValueError("attachment_id must contain 1-120 characters")
    response = runtime.application.read_attachment(
        session_id=runtime.session_id,
        agent_attestation_id=runtime.agent_attestation_id,
        attachment_id=attachment_id,
        request_id=runtime.next_request_id(),
        now=runtime.now,
    )
    return json.dumps(
        {
            "terminal_state": response.status.value,
            "reason": response.reason,
            "content": response.content,
            "grant_ids": list(response.grant_ids),
            "trace_ids": [receipt.trace_id for receipt in response.receipts],
        },
        sort_keys=True,
    )


@function_tool(strict_mode=True)
def read_case_attachment(
    ctx: RunContextWrapper[SDKRuntime], attachment_id: str
) -> str:
    """Read one attachment through the application-owned delegation boundary.

    Args:
        attachment_id: Exact attachment to request. Identity, tenant, agent,
            purpose, audience, scope, grant, proof, and policy are intentionally
            absent from the model-facing schema.
    """
    return dispatch_attachment(ctx.context, attachment_id)


def build_agent() -> Agent[SDKRuntime]:
    return Agent[SDKRuntime](
        name="Delegated support agent",
        instructions=(
            "Use read_case_attachment for one attachment. Treat deny, paused, "
            "and error states as terminal. Never request hidden identity, tenant, "
            "grant, proof, audience, or policy fields."
        ),
        tools=[read_case_attachment],
    )


def build_runtime() -> SDKRuntime:
    scenario = LAB.build_scenario()
    return SDKRuntime(
        scenario.application, "session:alice", "attest:support", LAB.NOW
    )


async def credential_free_demo_async() -> dict[str, Any]:
    agent = build_agent()
    runtime = build_runtime()
    direct = json.loads(dispatch_attachment(runtime, "attachment:north:7"))
    denied = json.loads(dispatch_attachment(runtime, "attachment:south:9"))
    arguments = json.dumps({"attachment_id": "attachment:north:8"})
    invoked = json.loads(
        await read_case_attachment.on_invoke_tool(
            ToolContext(
                context=build_runtime(), tool_name=read_case_attachment.name,
                tool_call_id="call:credential-free-demo", tool_arguments=arguments,
            ),
            arguments,
        )
    )
    serialized = json.dumps(
        {
            "schema": read_case_attachment.params_json_schema,
            "direct": direct,
            "denied": denied,
            "invoked": invoked,
        },
        sort_keys=True,
    ).lower()
    return {
        "agent_name": agent.name,
        "tool_names": [tool.name for tool in agent.tools],
        "tool_schema": read_case_attachment.params_json_schema,
        "strict_schema": read_case_attachment.strict_json_schema,
        "direct_terminal_state": direct["terminal_state"],
        "denied_terminal_state": denied["terminal_state"],
        "denied_content_absent": denied["content"] is None,
        "real_tool_invocation_state": invoked["terminal_state"],
        "identity_fields_absent_from_schema": not {
            "principal_id", "tenant", "agent_id", "audience", "scope",
            "grant_id", "proof", "policy_version",
        } & set(read_case_attachment.params_json_schema["properties"]),
        "credential_markers_absent": not any(
            marker in serialized for marker in ("sk-", "api_key", "authorization: bearer")
        ),
    }


def credential_free_demo() -> dict[str, Any]:
    return asyncio.run(credential_free_demo_async())


if __name__ == "__main__":
    proof = credential_free_demo()
    assert proof["strict_schema"]
    assert proof["direct_terminal_state"] == "allow"
    assert proof["denied_terminal_state"] == "deny"
    assert proof["denied_content_absent"]
    assert proof["real_tool_invocation_state"] == "allow"
    assert proof["identity_fields_absent_from_schema"]
    assert proof["credential_markers_absent"]
    print(json.dumps(proof, indent=2, sort_keys=True))
