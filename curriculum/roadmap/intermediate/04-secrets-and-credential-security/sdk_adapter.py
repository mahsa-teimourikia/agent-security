"""Credential-free OpenAI Agents SDK adapter for Intermediate 04.

The strict model-facing tool exposes one resource identifier. Workload identity,
tenant, audience, purpose, operation, credential lease, secret metadata, raw
credential bytes, and request IDs remain in trusted application context.
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
    "intermediate_04_credentials_lab", Path(__file__).with_name("lab.py")
)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


@dataclass
class SDKRuntime:
    """Server-owned runtime context; never serialize credential material into it."""

    application: Any
    attestation_id: str
    now: Any
    request_counter: int = 0

    def next_request_id(self) -> str:
        self.request_counter += 1
        return f"sdk:policy:{self.request_counter}"


def dispatch_policy(runtime: SDKRuntime, policy_id: str) -> str:
    if not policy_id or len(policy_id) > 120:
        raise ValueError("policy_id must contain 1-120 characters")
    response = runtime.application.read_policy(
        attestation_id=runtime.attestation_id,
        policy_id=policy_id,
        request_id=runtime.next_request_id(),
        now=runtime.now,
    )
    return json.dumps(
        {
            "terminal_state": response.status.value,
            "reason": response.reason,
            "content": response.content,
            "trace_ids": [receipt.trace_id for receipt in response.receipts],
        },
        sort_keys=True,
    )


@function_tool(strict_mode=True)
def read_policy_record(ctx: RunContextWrapper[SDKRuntime], policy_id: str) -> str:
    """Read one authorized policy through the application credential boundary.

    Args:
        policy_id: Exact policy record to request. Identity, tenant, audience,
            scope, credential, secret reference, token, and lifetime are
            intentionally absent from the model-facing schema.
    """
    return dispatch_policy(ctx.context, policy_id)


def build_agent() -> Agent[SDKRuntime]:
    return Agent[SDKRuntime](
        name="Credential-safe support agent",
        instructions=(
            "Use read_policy_record for one policy. Treat deny and error as "
            "terminal. Never request, infer, print, remember, or forward "
            "credentials, secret references, identity, tenant, audience, or scope."
        ),
        tools=[read_policy_record],
    )


def build_runtime() -> SDKRuntime:
    scenario = LAB.build_scenario()
    return SDKRuntime(scenario.application, "attest:support", LAB.NOW)


async def credential_free_demo_async() -> dict[str, Any]:
    agent = build_agent()
    runtime = build_runtime()
    direct = json.loads(dispatch_policy(runtime, "policy:north:7"))
    denied = json.loads(dispatch_policy(runtime, "policy:south:9"))
    arguments = json.dumps({"policy_id": "policy:north:8"})
    invoked = json.loads(
        await read_policy_record.on_invoke_tool(
            ToolContext(
                context=build_runtime(), tool_name=read_policy_record.name,
                tool_call_id="call:credential-free-demo", tool_arguments=arguments,
            ),
            arguments,
        )
    )
    serialized = json.dumps(
        {
            "schema": read_policy_record.params_json_schema,
            "direct": direct,
            "denied": denied,
            "invoked": invoked,
        },
        sort_keys=True,
    )
    properties = set(read_policy_record.params_json_schema["properties"])
    return {
        "agent_name": agent.name,
        "tool_names": [tool.name for tool in agent.tools],
        "tool_schema": read_policy_record.params_json_schema,
        "strict_schema": read_policy_record.strict_json_schema,
        "direct_terminal_state": direct["terminal_state"],
        "denied_terminal_state": denied["terminal_state"],
        "denied_content_absent": denied["content"] is None,
        "real_tool_invocation_state": invoked["terminal_state"],
        "trusted_fields_absent_from_schema": not {
            "attestation_id", "workload_id", "tenant", "audience", "purpose",
            "scope", "operation", "credential", "secret", "token", "lease_id",
        } & properties,
        "lease_ids_absent_from_results": all(
            "lease_id" not in result for result in (direct, denied, invoked)
        ),
        "raw_material_absent": not any(
            marker in serialized for marker in (
                LAB._POLICY_MATERIAL_V1,
                LAB._POLICY_MATERIAL_V2,
                LAB._TICKET_MATERIAL_V1,
            )
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
    assert proof["trusted_fields_absent_from_schema"]
    assert proof["lease_ids_absent_from_results"]
    assert proof["raw_material_absent"]
    print(json.dumps(proof, indent=2, sort_keys=True))
