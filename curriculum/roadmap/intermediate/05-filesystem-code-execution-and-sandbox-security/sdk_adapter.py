"""OpenAI Agents SDK adapter for the Intermediate 05 sandbox boundary.

The model selects registered archive and program identifiers. Authenticated
workload, tenant, image, policy, budgets, network mode, grant, and sandbox
lifecycle remain in trusted application context. No untrusted host code runs.
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
    "intermediate_05_sandbox_lab", Path(__file__).with_name("lab.py")
)
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


@dataclass
class SDKRuntime:
    application: Any
    attestation_id: str
    now: Any
    request_counter: int = 0

    def next_request_id(self) -> str:
        self.request_counter += 1
        return f"sdk:sandbox:{self.request_counter}"


def dispatch_analysis(runtime: SDKRuntime, archive_id: str, program_id: str) -> str:
    for label, value in (("archive_id", archive_id), ("program_id", program_id)):
        if not value or len(value) > 120:
            raise ValueError(f"{label} must contain 1-120 characters")
    response = runtime.application.analyze_archive(
        attestation_id=runtime.attestation_id,
        archive_id=archive_id,
        program_id=program_id,
        request_id=runtime.next_request_id(),
        now=runtime.now,
    )
    return json.dumps(
        {
            "terminal_state": response.status.value,
            "reason": response.reason,
            "report": response.report,
            "trace_ids": [receipt.trace_id for receipt in response.receipts],
        },
        sort_keys=True,
    )


@function_tool(strict_mode=True)
def analyze_uploaded_archive(
    ctx: RunContextWrapper[SDKRuntime], archive_id: str, program_id: str
) -> str:
    """Run one registered program against one uploaded archive.

    Args:
        archive_id: Identifier for the uploaded archive selected by the user.
        program_id: Identifier for an untrusted program fixture to evaluate.
    """
    return dispatch_analysis(ctx.context, archive_id, program_id)


def build_agent() -> Agent[SDKRuntime]:
    return Agent[SDKRuntime](
        name="Sandbox-bound archive analyst",
        instructions=(
            "Use analyze_uploaded_archive with registered identifiers. Treat deny "
            "and error as terminal. Never invent identity, tenant, filesystem roots, "
            "network policy, resource limits, image, sandbox IDs, or execution grants."
        ),
        tools=[analyze_uploaded_archive],
    )


def build_runtime() -> SDKRuntime:
    scenario = LAB.build_scenario()
    return SDKRuntime(scenario.application, "attest:north", LAB.NOW)


async def sdk_boundary_demo_async() -> dict[str, Any]:
    agent = build_agent()
    runtime = build_runtime()
    safe = json.loads(
        dispatch_analysis(runtime, "archive:north:safe", "program:safe")
    )
    network = json.loads(
        dispatch_analysis(runtime, "archive:north:safe", "program:network")
    )
    cross_tenant = json.loads(
        dispatch_analysis(runtime, "archive:south:safe", "program:safe")
    )
    arguments = json.dumps(
        {"archive_id": "archive:north:safe", "program_id": "program:safe"}
    )
    invoked = json.loads(
        await analyze_uploaded_archive.on_invoke_tool(
            ToolContext(
                context=build_runtime(),
                tool_name=analyze_uploaded_archive.name,
                tool_call_id="call:sandbox-boundary-demo",
                tool_arguments=arguments,
            ),
            arguments,
        )
    )
    properties = set(analyze_uploaded_archive.params_json_schema["properties"])
    return {
        "agent_name": agent.name,
        "tool_names": [tool.name for tool in agent.tools],
        "tool_schema": analyze_uploaded_archive.params_json_schema,
        "strict_schema": analyze_uploaded_archive.strict_json_schema,
        "safe_terminal_state": safe["terminal_state"],
        "network_terminal_state": network["terminal_state"],
        "cross_tenant_terminal_state": cross_tenant["terminal_state"],
        "real_tool_invocation_state": invoked["terminal_state"],
        "trusted_fields_absent_from_schema": not {
            "attestation_id", "workload_id", "tenant", "workspace_root",
            "network_enabled", "allowed_syscalls", "resource_limits",
            "image_digest", "grant_id", "sandbox_id",
        } & properties,
        "internal_handles_absent_from_results": all(
            not {"grant_id", "sandbox_id"} & set(result)
            for result in (safe, network, cross_tenant, invoked)
        ),
    }


def sdk_boundary_demo() -> dict[str, Any]:
    return asyncio.run(sdk_boundary_demo_async())


if __name__ == "__main__":
    proof = sdk_boundary_demo()
    assert proof["strict_schema"]
    assert proof["safe_terminal_state"] == "allow"
    assert proof["network_terminal_state"] == "deny"
    assert proof["cross_tenant_terminal_state"] == "deny"
    assert proof["real_tool_invocation_state"] == "allow"
    assert proof["trusted_fields_absent_from_schema"]
    assert proof["internal_handles_absent_from_results"]
    print(json.dumps(proof, indent=2, sort_keys=True))
