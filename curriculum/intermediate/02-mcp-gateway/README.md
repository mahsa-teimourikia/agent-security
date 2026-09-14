# Intermediate 02 — MCP Gateway Security

## Capability

Design and evaluate an MCP gateway that treats discovery and model output as
untrusted inputs while independently enforcing server trust, identity, token
audience, tenant, scope, schemas, quotas, and audit at the call boundary.

## Learning outcomes

After this course, you can:

1. distinguish MCP discovery metadata from authentication and authorization;
2. bind an invocation to trusted subject, tenant, audience, scope, and expiry;
3. prevent token passthrough and confused-deputy behavior;
4. validate exact tool schemas and rate limits before execution; and
5. evaluate attacks with privacy-aware decision receipts.

Prerequisite: [Intermediate 01 — Identity Propagation](../01-identity-propagation/README.md).

Next: [Intermediate 03 — Incident Response and Recovery](../03-incident-recovery/README.md).

## Governing invariant

> Discovery can propose a server or tool. Only the trusted gateway may grant
> an invocation, and the inbound token must never become a downstream token.

An MCP server description can be useful and still be malicious. A tool name
does not prove server identity, the caller’s authority, or the safety of its
arguments. The gateway is therefore a policy enforcement point, not a proxy
that blindly forwards whatever the model assembled.

## Threat model and architecture

Assets include user data, connector credentials, external side effects, and
the decision trail. Attackers may influence prompts, tool descriptions, tool
arguments, registered servers, or stolen tokens. They do not control the
authenticated application identity or the gateway policy.

```text
untrusted discovery + model proposal
                 │
                 ▼
        ┌───────────────────┐
        │ MCP gateway       │◄── trusted identity + audience-bound token
        │ server allowlist  │
        │ tool schema       │
        │ tenant + scope    │
        │ expiry + quota    │
        └─────────┬─────────┘
                  │ narrow gateway capability (never inbound token)
                  ▼
          simulated MCP server
                  │
                  ▼
     result remains untrusted data + decision receipt
```

The lab uses in-memory dataclasses instead of OAuth or network calls. That is a
teaching simplification, not a production security boundary. Production MCP
over HTTP should follow the current authorization specification, validate that
tokens are intended for the MCP server, and acquire a separate token for any
upstream API instead of passing through the client token.

## Attack walkthrough

The safe case uses an authenticated `research-agent`, tenant `north`, an
unexpired token for audience `mcp-gateway`, and the exact `search_policy`
schema. Then change one boundary at a time:

| Attack | Expected gateway reason |
| --- | --- |
| unregistered server advertises a familiar tool | `untrusted-server` |
| token belongs to a different subject or tenant | `identity-binding` |
| token was issued for an enterprise API | `token-audience` |
| token is expired | `token-expired` |
| caller lacks the tool scope | `capability-scope` |
| proposal adds an `admin` field | `argument-schema` |
| caller exceeds the per-tool quota | `rate-limit` |

The receipt records a hash of arguments and a fingerprint of the token ID. It
does not record the token, raw prompt, private model reasoning, or tool result.

## Run the lab

From the repository root:

```bash
python3 curriculum/intermediate/02-mcp-gateway/02_mcp_gateway.py
jupyter notebook curriculum/intermediate/02-mcp-gateway/02_mcp_gateway.ipynb
```

The notebook runs the safe invocation, injects boundary failures, checks token
non-disclosure, and computes a denial-reason summary.

## Evaluation and production checklist

Measure unknown-server acceptance, audience-confusion success, scope bypass,
schema bypass, valid-call blocking, quota enforcement, and decision trace
coverage. Before production, also require TLS and server identity validation,
OAuth consent and revocation, secret isolation, egress controls, response-size
limits, tool-result isolation, centralized audit, incident ownership, and
dependency inventory.

Residual risks include compromise of an allowlisted server, malicious but
schema-valid results, policy misconfiguration, and stolen valid credentials.
Courses 14, 16, 23, 26, and 30 in the expansion roadmap address those layers.

## Checkpoint

A discovered MCP server advertises `delete_customer`, and the user’s token is
valid for the gateway but lacks that tool’s scope. What should happen?

- A. Discovery grants the capability.
- B. The gateway denies the call before execution and records a scoped receipt.
- C. The gateway forwards the token so the server can decide.

**Answer: B.** Discovery is metadata, not authority. Forwarding the inbound
token also creates audience and confused-deputy risk.

## References

- [MCP specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic)
- [MCP authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OAuth 2.0 Resource Indicators — RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

This published lesson is the concise gateway path. The broader canonical
[roadmap course 16](../16-mcp-security/README.md) extends it to resources,
prompts, result poisoning, protocol lifecycle, and supply-chain boundaries.
