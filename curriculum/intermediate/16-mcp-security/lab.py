"""Offline MCP gateway policy: discovery is metadata, never authorization."""
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256


@dataclass(frozen=True)
class Call:
    client: str
    server: str
    tool: str
    tenant: str
    scopes: frozenset[str]
    arguments: dict[str, str]
    token_audience: str


TRUSTED_SERVERS = {"mcp-research-v1": {"search_policy", "read_document"}}


def dispatch(call: Call, *, expected_audience: str = "mcp-gateway", now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    receipt = {"time": now.isoformat(), "client": call.client, "server": call.server,
               "tool": call.tool, "tenant": call.tenant,
               "arguments_hash": sha256(repr(sorted(call.arguments.items())).encode()).hexdigest()[:16]}
    if call.client != "agent-gateway": return {"decision": "deny", "reason": "client-authentication", **receipt}
    if call.token_audience != expected_audience: return {"decision": "deny", "reason": "token-audience", **receipt}
    if call.server not in TRUSTED_SERVERS: return {"decision": "deny", "reason": "untrusted-server", **receipt}
    if call.tool not in TRUSTED_SERVERS[call.server] or call.tool not in call.scopes:
        return {"decision": "deny", "reason": "capability-scope", **receipt}
    if call.tenant not in {"north", "south"} or set(call.arguments) - {"query", "document_id"}:
        return {"decision": "deny", "reason": "tenant-or-schema", **receipt}
    return {"decision": "allow", "reason": "authenticated-scoped-call", **receipt}


if __name__ == "__main__":
    safe = Call("agent-gateway", "mcp-research-v1", "search_policy", "north", frozenset({"search_policy"}), {"query": "retention"}, "mcp-gateway")
    assert dispatch(safe)["decision"] == "allow"
    assert dispatch(Call(**{**safe.__dict__, "server": "mcp-unknown"}))["decision"] == "deny"
    assert dispatch(Call(**{**safe.__dict__, "token_audience": "enterprise-api"}))["decision"] == "deny"
    assert dispatch(Call(**{**safe.__dict__, "arguments": {"query": "x", "admin": "true"}}))["decision"] == "deny"
    print("MCP gateway attack cases passed")
