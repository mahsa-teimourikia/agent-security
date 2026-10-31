"""Official SDK bridge for the Advanced 05 protocol-composition boundary.

The adapter constructs real A2A 1.0, MCP 2026-07-28, and HTTPX request
objects. It never sends a request, calls a model, or forwards the synthetic
inbound credential. The reusable lab remains the source of authorization and
provenance decisions; SDK schemas only constrain protocol shape.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata
import importlib.util
from pathlib import Path
import sys

from a2a import types as a2a_types
from google.protobuf.json_format import MessageToDict
import httpx
from mcp import types as mcp_types


SPEC = importlib.util.spec_from_file_location(
    "advanced_05_protocol_composition_core", Path(__file__).with_name("lab.py")
)
assert SPEC and SPEC.loader
core = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, core)
SPEC.loader.exec_module(core)


@dataclass
class CompositionSdkContext:
    gateway: core.ProtocolCompositionGateway
    principals: dict[str, core.Principal]
    request: core.IngressRequest
    ingress: core.Decision
    a2a: core.Decision | None = None
    mcp: core.Decision | None = None
    api: core.Decision | None = None
    result: core.Decision | None = None
    release: core.Decision | None = None


def _traceparent(grant: core.HopGrant) -> str:
    return f"00-{grant.trace_id}-{grant.span_id}-01"


def start_context(
    task_note: str = "Summarize the approved support case evidence.",
    *,
    request_id: str = "request:sdk:composition",
) -> CompositionSdkContext:
    """Authenticate the web request before constructing a protocol message."""

    if not isinstance(task_note, str) or not task_note or len(task_note) > 1000:
        raise ValueError("task_note must contain 1-1000 characters")
    gateway, principals = core.build_scenario()
    request = core.ingress_request(request_id=request_id, note=task_note)
    ingress = gateway.start_request(
        principals["user"],
        core.token_for(principals["user"]),
        request,
        now=core.NOW,
        step=0,
    )
    if not ingress.allowed or not ingress.grant:
        raise PermissionError(ingress.reason)
    return CompositionSdkContext(gateway, principals, request, ingress)


def build_a2a_request(
    context: CompositionSdkContext,
) -> a2a_types.SendMessageRequest:
    """Exchange web authority, then build an official A2A request."""

    assert context.ingress.grant
    proposal = core.translation_for(
        context.gateway,
        context.ingress.grant,
        core.Protocol.A2A,
        content=context.request.note,
    )
    decision = context.gateway.translate(
        context.principals["supervisor"], proposal, now=core.NOW, step=1
    )
    if not decision.allowed or not decision.grant:
        raise PermissionError(decision.reason)
    context.a2a = decision
    return a2a_types.SendMessageRequest(
        tenant=decision.grant.tenant,
        message=a2a_types.Message(
            message_id=f"message:{context.request.request_id}",
            context_id=f"context:{context.request.resource_id}",
            role=a2a_types.Role.ROLE_USER,
            parts=[
                a2a_types.Part(
                    text=context.request.note,
                    media_type="text/plain",
                )
            ],
        ),
        configuration=a2a_types.SendMessageConfiguration(
            accepted_output_modes=["application/json"],
            history_length=0,
            return_immediately=True,
        ),
    )


def build_mcp_request(context: CompositionSdkContext) -> mcp_types.CallToolRequest:
    """Exchange A2A authority, then build an official MCP tool request."""

    if not context.a2a or not context.a2a.grant:
        raise RuntimeError("build the A2A request first")
    proposal = core.translation_for(
        context.gateway,
        context.a2a.grant,
        core.Protocol.MCP,
        content="Call the approved case lookup tool.",
    )
    decision = context.gateway.translate(
        context.principals["specialist"], proposal, now=core.NOW, step=2
    )
    if not decision.allowed or not decision.grant:
        raise PermissionError(decision.reason)
    context.mcp = decision
    return mcp_types.CallToolRequest(
        params=mcp_types.CallToolRequestParams(
            name="lookup_case",
            arguments={"case_id": decision.grant.resource_id},
            _meta={"traceparent": _traceparent(decision.grant)},
        )
    )


def build_api_request(context: CompositionSdkContext) -> httpx.Request:
    """Exchange MCP authority, then construct—but do not send—an API request."""

    if not context.mcp or not context.mcp.grant:
        raise RuntimeError("build the MCP request first")
    proposal = core.translation_for(
        context.gateway,
        context.mcp.grant,
        core.Protocol.HTTP_API,
        content="Read one server-selected case summary.",
    )
    decision = context.gateway.translate(
        context.principals["mcp"], proposal, now=core.NOW, step=3
    )
    if not decision.allowed or not decision.grant:
        raise PermissionError(decision.reason)
    context.api = decision
    return httpx.Request(
        "GET",
        (
            "https://records.example.test/api/cases/"
            f"{decision.grant.resource_id}?representation=summary"
        ),
        headers={
            "accept": "application/json",
            "traceparent": _traceparent(decision.grant),
            "x-request-id": decision.grant.root_request_id,
        },
        extensions={"composition_grant_id": decision.grant.grant_id},
    )


def admit_and_release(context: CompositionSdkContext) -> core.ReleasedResult:
    """Admit synthetic API evidence and release only its verified summary."""

    if not context.api or not context.api.grant:
        raise RuntimeError("build the API request first")
    result = context.gateway.admit_api_result(
        context.principals["records"],
        core.api_result_for(
            context.api.grant,
            result_id=f"result:{context.request.request_id}",
        ),
        now=core.NOW,
        step=4,
    )
    if not result.allowed or not result.artifact:
        raise PermissionError(result.reason)
    context.result = result
    release = context.gateway.release_result(
        context.principals["user"],
        core.ReleaseProposal(
            release_id=f"release:{context.request.request_id}",
            ingress_grant_id=context.ingress.grant.grant_id,
            artifact_id=result.artifact.artifact_id,
            tenant=context.ingress.grant.tenant,
            resource_id=context.ingress.grant.resource_id,
        ),
        now=core.NOW,
        step=5,
    )
    if not release.allowed or not release.released:
        raise PermissionError(release.reason)
    context.release = release
    return release.released


def credential_free_demo(
    task_note: str = "Summarize the approved support case evidence.",
) -> dict[str, object]:
    context = start_context(task_note)
    a2a_request = build_a2a_request(context)
    mcp_request = build_mcp_request(context)
    api_request = build_api_request(context)
    released = admit_and_release(context)
    mcp_payload = mcp_request.model_dump(by_alias=True, exclude_none=True)
    return {
        "a2a_sdk_version": importlib.metadata.version("a2a-sdk"),
        "mcp_sdk_version": importlib.metadata.version("mcp"),
        "httpx_version": importlib.metadata.version("httpx"),
        "a2a_protocol_version": core.A2A_PROTOCOL_VERSION,
        "mcp_protocol_version": core.MCP_PROTOCOL_VERSION,
        "a2a_request": MessageToDict(
            a2a_request, preserving_proto_field_name=True
        ),
        "mcp_request": mcp_payload,
        "api_request": {
            "method": api_request.method,
            "url": str(api_request.url),
            "headers": {
                name: value
                for name, value in api_request.headers.items()
                if name in {"accept", "traceparent", "x-request-id"}
            },
        },
        "audiences": [
            context.ingress.grant.audience,
            context.a2a.grant.audience,
            context.mcp.grant.audience,
            context.api.grant.audience,
        ],
        "protocol_scopes": [
            sorted(context.ingress.grant.protocol_scopes),
            sorted(context.a2a.grant.protocol_scopes),
            sorted(context.mcp.grant.protocol_scopes),
            sorted(context.api.grant.protocol_scopes),
        ],
        "trace_ids": sorted(
            {grant.trace_id for grant in context.gateway.grants.values()}
        ),
        "released": released,
        "inbound_token_forwarded": any(
            "synthetic-inbound-token" in str(value)
            for value in (a2a_request, mcp_payload, api_request.headers)
        ),
        "identity_in_protocol_payload": (
            "alice" in str(MessageToDict(a2a_request))
            or "alice" in str(mcp_payload)
            or "alice" in str(api_request.url)
        ),
        "model_calls": 0,
        "network_calls": 0,
    }


if __name__ == "__main__":
    proof = credential_free_demo()
    print(
        {
            key: proof[key]
            for key in (
                "a2a_sdk_version",
                "mcp_sdk_version",
                "a2a_protocol_version",
                "mcp_protocol_version",
                "audiences",
                "protocol_scopes",
                "trace_ids",
                "inbound_token_forwarded",
                "identity_in_protocol_payload",
                "model_calls",
                "network_calls",
            )
        }
    )
