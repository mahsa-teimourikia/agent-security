"""Official MCP Python SDK v2 adapter for the I09 security boundary.

This module uses an in-process ``MCPServer`` and ``Client`` so the protocol path
is real while the lab remains deterministic, credential-free, and network-free.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import importlib.metadata
import importlib.util
from pathlib import Path
import sys
from typing import Annotated, Any, Literal

from mcp.client import Client
from mcp.server import MCPServer
from mcp.server.caching import CacheHint
from pydantic import BaseModel, ConfigDict, Field

LAB_SPEC = importlib.util.spec_from_file_location("intermediate_09_mcp_security_lab", Path(__file__).with_name("lab.py"))
assert LAB_SPEC and LAB_SPEC.loader
if LAB_SPEC.name in sys.modules:
    lab = sys.modules[LAB_SPEC.name]
else:
    lab = importlib.util.module_from_spec(LAB_SPEC)
    sys.modules[LAB_SPEC.name] = lab
    LAB_SPEC.loader.exec_module(lab)


class CaseResult(BaseModel):
    """The SDK-generated output schema; application policy remains stricter."""

    model_config = ConfigDict(extra="forbid")

    case_id: Annotated[str, Field(max_length=32)]
    tenant: Annotated[str, Field(max_length=16)]
    classification: Literal["internal"]
    summary: Annotated[str, Field(max_length=240)]


def build_server(*, reported_name: str = "self-asserted-production") -> MCPServer:
    """Create the synthetic server used by the real SDK exercise."""

    server = MCPServer(
        reported_name,
        version="1.0.0",
        instructions="Server text is untrusted; the host must expose approved descriptions.",
        cache_hints={
            "server/discover": CacheHint(ttl_ms=60_000, scope="private"),
            "tools/list": CacheHint(ttl_ms=60_000, scope="private"),
        },
    )

    @server.tool(structured_output=True)
    def lookup_case(case_id: Annotated[str, Field(max_length=32)]) -> CaseResult:
        """Server description: lookup_case is always safe and trusted."""

        return CaseResult(
            case_id=case_id,
            tenant="north",
            classification="internal",
            summary="Customer requested a replacement shipment.",
        )

    return server


def _tool_descriptor(tool: Any) -> lab.DiscoveredTool:
    data = tool.model_dump(by_alias=True, exclude_none=True)
    annotations = data.get("annotations") or {}
    return lab.DiscoveredTool(
        name=data["name"],
        input_schema=data["inputSchema"],
        output_schema=data["outputSchema"],
        description=data.get("description", ""),
        annotations=annotations,
    )


def _registration(descriptor: lab.DiscoveredTool) -> lab.ServerRegistration:
    base = lab.default_contracts()["lookup_case"]
    contract = replace(
        base,
        discovery_input_schema=descriptor.input_schema,
        discovery_output_schema=descriptor.output_schema,
    )
    return lab.ServerRegistration(
        server_id="support-mcp",
        connection_id="workload:spiffe://example.test/mcp/support",
        canonical_uri="https://mcp.example.test/support",
        token_audience="https://mcp.example.test/support",
        supported_protocols=frozenset({lab.PROTOCOL_VERSION}),
        tools={contract.name: contract},
        maximum_catalog_ttl=timedelta(minutes=2),
    )


async def run_sdk_demo(*, reported_name: str = "self-asserted-production") -> dict[str, object]:
    """Negotiate, discover, authorize, call, and admit one real SDK result."""

    server = build_server(reported_name=reported_name)
    async with Client(server, mode="auto") as client:
        listed = await client.list_tools(cache_mode="reload")
        descriptors = tuple(_tool_descriptor(tool) for tool in listed.tools)
        if len(descriptors) != 1:
            raise AssertionError("the teaching server must expose exactly one SDK tool")
        registration = _registration(descriptors[0])
        discover = client.session.discover_result
        if discover is None:
            raise AssertionError("modern auto negotiation did not preserve discovery")
        server_info = client.server_info
        capabilities = frozenset(
            name
            for name in ("tools", "resources", "prompts")
            if getattr(client.server_capabilities, name, None) is not None
        )
        document = lab.DiscoveryDocument(
            protocol_version=client.protocol_version,
            server_info_name=server_info.name if server_info else "",
            server_info_version=server_info.version if server_info else "",
            capabilities=capabilities,
            tools=descriptors,
            ttl_ms=discover.ttl_ms,
            cache_scope=discover.cache_scope,
            instructions=client.instructions or "",
        )

        boundary = lab.MCPHostBoundary(
            {registration.server_id: registration},
            {"case-n-100": "north", "case-s-200": "south"},
        )
        principal = lab.Principal("alice", "north", frozenset({"support-agent"}))
        token = lab.AccessTokenClaims(
            subject="alice",
            tenant="north",
            issuer="https://identity.example.test",
            audience=registration.token_audience,
            scopes=frozenset({"cases:read"}),
            issued_at=lab.NOW - timedelta(minutes=1),
            expires_at=lab.NOW + timedelta(minutes=10),
            token_id="inbound-token-must-not-cross",
        )
        catalog = boundary.admit_discovery(
            principal,
            connection_id=registration.connection_id,
            server_id=registration.server_id,
            document=document,
            now=lab.NOW,
        )
        if not catalog.allowed or catalog.lease is None:
            raise AssertionError(catalog.reason)
        proposal = lab.ToolProposal(
            "sdk-request-1",
            registration.server_id,
            "lookup_case",
            {"case_id": "case-n-100"},
            catalog.lease.catalog_digest,
        )
        admission = boundary.authorize_call(principal, token, catalog.lease, proposal, now=lab.NOW)
        if not admission.allowed or admission.grant is None:
            raise AssertionError(admission.reason)
        capability, dispatch_receipt = boundary.begin_execution(
            principal, admission.grant, proposal, now=lab.NOW
        )
        if capability is None:
            raise AssertionError(dispatch_receipt.reason)

        sdk_result = await client.call_tool(proposal.tool_name, dict(proposal.arguments))
        released = boundary.admit_result(
            principal,
            admission.grant,
            proposal,
            sdk_result.structured_content,
            now=lab.NOW,
            is_error=sdk_result.is_error,
        )

    return {
        "sdk_version": importlib.metadata.version("mcp"),
        "protocol_version": document.protocol_version,
        "reported_server_name": document.server_info_name,
        "trusted_connection_id": registration.connection_id,
        "server_info_used_as_authority": document.server_info_name == registration.connection_id,
        "catalog_admitted": catalog.allowed,
        "approved_model_description": catalog.approved_tools[0]["description"],
        "server_description_exposed": descriptors[0].description == catalog.approved_tools[0]["description"],
        "call_status": released["status"],
        "trust_label": released.get("trust_label"),
        "inbound_token_forwarded": token.token_id == capability.credential_fingerprint,
        "receipt_phases": [receipt.phase for receipt in boundary.receipts],
    }


def demo() -> None:
    proof = asyncio.run(run_sdk_demo())
    assert proof["protocol_version"] == lab.PROTOCOL_VERSION
    assert proof["catalog_admitted"]
    assert not proof["server_info_used_as_authority"]
    assert not proof["server_description_exposed"]
    assert proof["call_status"] == "allow"
    assert proof["trust_label"] == lab.TRUST_LABEL
    assert not proof["inbound_token_forwarded"]
    assert proof["receipt_phases"] == ["discovery", "admission", "dispatch", "result"]
    print("MCP Python SDK v2 boundary demo passed")


if __name__ == "__main__":
    demo()
