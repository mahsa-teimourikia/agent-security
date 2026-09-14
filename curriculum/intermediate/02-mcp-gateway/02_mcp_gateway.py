"""Deterministic MCP gateway with independent authorization and audit receipts.

Discovery data and model-proposed arguments are deliberately untrusted. The
gateway derives identity, tenant, token audience, and scope from trusted
application state before a simulated downstream call can occur.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Callable


@dataclass(frozen=True)
class ClientIdentity:
    subject: str
    tenant: str
    authenticated: bool = True


@dataclass(frozen=True)
class AccessToken:
    subject: str
    tenant: str
    audience: str
    scopes: frozenset[str]
    expires_at: datetime
    token_id: str


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_scope: str
    allowed_arguments: frozenset[str]


@dataclass(frozen=True)
class ToolCall:
    server: str
    tool: str
    arguments: dict[str, str]


@dataclass(frozen=True)
class DecisionReceipt:
    decision: str
    reason: str
    subject: str
    tenant: str
    server: str
    tool: str
    token_fingerprint: str
    arguments_hash: str
    observed_at: str


@dataclass
class Gateway:
    trusted_servers: dict[str, dict[str, ToolSpec]]
    audience: str = "mcp-gateway"
    per_subject_limit: int = 3
    usage: dict[tuple[str, str], int] = field(default_factory=dict)
    receipts: list[DecisionReceipt] = field(default_factory=list)

    def dispatch(
        self,
        identity: ClientIdentity,
        token: AccessToken,
        proposal: ToolCall,
        *,
        now: datetime,
        execute: Callable[[ToolCall, str], dict[str, str]] | None = None,
    ) -> dict[str, object]:
        """Authorize a proposal and optionally invoke a narrow execution stub.

        The downstream credential is a gateway-created identifier. The inbound
        access token is never returned or forwarded.
        """
        reason = self._reason(identity, token, proposal, now=now)
        receipt = self._receipt(identity, token, proposal, now, reason)
        self.receipts.append(receipt)
        if reason != "authorized":
            return {"status": "deny", "receipt": receipt}

        key = (identity.subject, proposal.tool)
        self.usage[key] = self.usage.get(key, 0) + 1
        downstream_capability = f"gw:{identity.tenant}:{proposal.tool}"
        output = (execute or safe_execution_stub)(proposal, downstream_capability)
        return {"status": "allow", "receipt": receipt, "output": output}

    def _reason(
        self,
        identity: ClientIdentity,
        token: AccessToken,
        proposal: ToolCall,
        *,
        now: datetime,
    ) -> str:
        if not identity.authenticated:
            return "client-authentication"
        if token.subject != identity.subject or token.tenant != identity.tenant:
            return "identity-binding"
        if token.audience != self.audience:
            return "token-audience"
        if token.expires_at <= now:
            return "token-expired"
        tools = self.trusted_servers.get(proposal.server)
        if tools is None:
            return "untrusted-server"
        spec = tools.get(proposal.tool)
        if spec is None:
            return "unknown-tool"
        if spec.required_scope not in token.scopes:
            return "capability-scope"
        if set(proposal.arguments) != set(spec.allowed_arguments):
            return "argument-schema"
        if any(not isinstance(value, str) or not value.strip() for value in proposal.arguments.values()):
            return "argument-value"
        if self.usage.get((identity.subject, proposal.tool), 0) >= self.per_subject_limit:
            return "rate-limit"
        return "authorized"

    def _receipt(
        self,
        identity: ClientIdentity,
        token: AccessToken,
        proposal: ToolCall,
        now: datetime,
        reason: str,
    ) -> DecisionReceipt:
        token_fingerprint = sha256(token.token_id.encode()).hexdigest()[:12]
        arguments_hash = sha256(repr(sorted(proposal.arguments.items())).encode()).hexdigest()[:16]
        return DecisionReceipt(
            "allow" if reason == "authorized" else "deny",
            reason,
            identity.subject,
            identity.tenant,
            proposal.server,
            proposal.tool,
            token_fingerprint,
            arguments_hash,
            now.isoformat(),
        )


def safe_execution_stub(call: ToolCall, capability: str) -> dict[str, str]:
    """Return observable, non-sensitive output for an allowed teaching call."""
    return {
        "source": call.server,
        "tool": call.tool,
        "capability": capability,
        "result": f"preview:{call.arguments.get('query', call.arguments.get('document_id', ''))}",
    }


def demo() -> list[dict[str, object]]:
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    gateway = Gateway(
        {
            "research-mcp-v1": {
                "search_policy": ToolSpec("search_policy", "policy:search", frozenset({"query"})),
                "read_document": ToolSpec("read_document", "document:read", frozenset({"document_id"})),
            }
        },
        per_subject_limit=1,
    )
    identity = ClientIdentity("research-agent", "north")
    token = AccessToken(
        identity.subject,
        identity.tenant,
        "mcp-gateway",
        frozenset({"policy:search"}),
        now + timedelta(minutes=5),
        "opaque-token-7",
    )
    safe = ToolCall("research-mcp-v1", "search_policy", {"query": "retention"})
    cases = [
        gateway.dispatch(identity, token, safe, now=now),
        gateway.dispatch(identity, token, safe, now=now),
        gateway.dispatch(identity, token, ToolCall("evil-mcp", "search_policy", {"query": "x"}), now=now),
        gateway.dispatch(identity, token, ToolCall("research-mcp-v1", "search_policy", {"query": "x", "admin": "true"}), now=now),
    ]
    assert [case["status"] for case in cases] == ["allow", "deny", "deny", "deny"]
    assert "opaque-token-7" not in repr(cases)
    return cases


if __name__ == "__main__":
    for result in demo():
        print(result)
