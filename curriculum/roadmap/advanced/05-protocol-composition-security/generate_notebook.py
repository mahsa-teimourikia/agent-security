"""Generate the Advanced 05 protocol-composition notebook deterministically."""

from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "protocol_composition_security.ipynb"


def markdown(cell_id: str, source: str):
    cell = nbf.v4.new_markdown_cell(source.strip())
    cell["id"] = cell_id
    return cell


def code(cell_id: str, source: str):
    cell = nbf.v4.new_code_cell(source.strip())
    cell["id"] = cell_id
    return cell


def build_notebook():
    notebook = nbf.v4.new_notebook()
    notebook["metadata"] = {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3",
        },
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        markdown(
            "a05-title",
            """
# Advanced 05 — Protocol Composition Security

**Goal:** preserve identity, delegated authority, tenant and resource binding,
correlation, provenance, and exact replay semantics while translating a web
request through A2A 1.0, MCP 2026-07-28, and a downstream HTTP API.

This notebook is deterministic and credential-free. It constructs official
SDK objects but makes no network or model calls.

![Protocol-composition security architecture](architecture.svg)
""",
        ),
        markdown(
            "a05-contract",
            """
## Security contract

A protocol envelope is not authority. At every boundary, trusted application
code authenticates the caller, checks the exact transition, preserves
server-owned subject/tenant/resource state, exchanges a short-lived grant for
one audience, and records a content-free receipt. Trace headers correlate
events; they never authorize them.
""",
        ),
        code(
            "a05-imports",
            """
from dataclasses import asdict, replace
import json

import lab
import sdk_adapter as sdk
""",
        ),
        markdown(
            "a05-baseline-heading",
            """
## 1. Measure the unsafe composition baseline

The comparison forwards identity strings and bearer authority across
incompatible audiences. Its locally valid calls hide end-to-end control loss.
""",
        ),
        code(
            "a05-baseline",
            """
baseline = lab.unsafe_protocol_composition_baseline()
print(asdict(baseline))
assert baseline.attack_success_rate == 1.0
assert baseline.lost_identity_rate == 0.5
""",
        ),
        markdown(
            "a05-ingress-heading",
            """
## 2. Authenticate ingress and restart untrusted trace context

The gateway binds the authenticated principal and token claims to the tenant,
action, and resource. An external trace is useful as an untrusted link, not as
the internal authorization or trace root.
""",
        ),
        code(
            "a05-ingress",
            """
gateway, principals = lab.build_scenario()
request = lab.ingress_request(
    request_id="notebook:composition:1",
    external_traceparent="00-ffffffffffffffffffffffffffffffff-1111111111111111-01",
)
ingress = gateway.start_request(
    principals["user"], lab.token_for(principals["user"]), request,
    now=lab.NOW, step=0,
)
print({
    "decision": ingress.reason,
    "subject": ingress.grant.subject,
    "audience": ingress.grant.audience,
    "internal_trace": ingress.grant.trace_id,
})
assert ingress.allowed
assert ingress.grant.trace_id != "f" * 32
""",
        ),
        markdown(
            "a05-a2a-heading",
            """
## 3. Translate Web → A2A

Semantic authority remains `case.read`, while the wire scope changes to the
least A2A permission required for the specialist. The supervisor receives a
new grant for the specialist audience; it does not forward the web token.
""",
        ),
        code(
            "a05-a2a",
            """
a2a = gateway.translate(
    principals["supervisor"],
    lab.translation_for(gateway, ingress.grant, lab.Protocol.A2A),
    now=lab.NOW, step=1,
)
print({
    "semantic_authority": sorted(a2a.grant.authority),
    "wire_scope": sorted(a2a.grant.protocol_scopes),
    "audience": a2a.grant.audience,
    "parent": a2a.grant.parent_grant_id,
})
assert a2a.allowed and a2a.grant.parent_grant_id == ingress.grant.grant_id
""",
        ),
        markdown(
            "a05-official-a2a-heading",
            """
## 4. Construct the official A2A request after authorization

The SDK constrains the interoperable message shape. It does not decide who the
user is, which tenant owns the case, or which downstream action is allowed.
""",
        ),
        code(
            "a05-official-a2a",
            """
context = sdk.start_context(request_id="notebook:sdk:composition")
a2a_request = sdk.build_a2a_request(context)
print({
    "message_id": a2a_request.message.message_id,
    "tenant": a2a_request.tenant,
    "role": a2a_request.message.role,
    "parts": len(a2a_request.message.parts),
})
assert context.a2a.allowed
""",
        ),
        markdown(
            "a05-mcp-heading",
            """
## 5. Translate A2A → MCP

The A2A specialist is authenticated as the translator. The MCP tool request
contains the bounded case identifier and trace metadata—not subject, tenant,
OAuth token, or a model-authored scope.
""",
        ),
        code(
            "a05-mcp",
            """
mcp_request = sdk.build_mcp_request(context)
mcp_payload = mcp_request.model_dump(by_alias=True, exclude_none=True)
print(json.dumps(mcp_payload, indent=2, default=str))
assert mcp_payload["params"]["arguments"] == {"case_id": "case-n-100"}
assert set(mcp_payload["params"]["_meta"]) == {"traceparent"}
""",
        ),
        markdown(
            "a05-api-heading",
            """
## 6. Translate MCP → the records API

The adapter constructs but never sends an HTTPX request. Production transport
code would inject the exchanged records-API credential outside model-visible
state. Its absence here is deliberate and testable.
""",
        ),
        code(
            "a05-api",
            """
api_request = sdk.build_api_request(context)
print({
    "method": api_request.method,
    "url": str(api_request.url),
    "headers": dict(api_request.headers),
})
assert "authorization" not in api_request.headers
assert context.api.grant.audience == "https://records.example.test/api"
""",
        ),
        markdown(
            "a05-lineage-heading",
            """
## 7. Inspect the grant and receipt lineage

The trace is stable across hops, while audience, wire scope, actor, span, and
grant ID are hop-specific. Receipts contain decisions and fingerprints, not
credentials or business content.
""",
        ),
        code(
            "a05-lineage",
            """
grants = [context.ingress.grant, context.a2a.grant, context.mcp.grant, context.api.grant]
for grant in grants:
    print(grant.protocol.value, grant.actor_workload, grant.audience,
          sorted(grant.protocol_scopes), grant.trace_id, grant.span_id)
serialized_receipts = json.dumps([asdict(item) for item in context.gateway.receipts], default=str)
assert len({grant.audience for grant in grants}) == 4
assert len({grant.trace_id for grant in grants}) == 1
assert "synthetic-inbound-token-42" not in serialized_receipts
""",
        ),
        markdown(
            "a05-attacks-heading",
            """
## 8. Reject widening, audience confusion, credential forwarding, and hop skipping

These are composition attacks: each proposal resembles a usable protocol
message, but violates an end-to-end invariant.
""",
        ),
        code(
            "a05-attacks",
            """
g, p = lab.build_scenario()
start = g.start_request(
    p["user"], lab.token_for(p["user"]),
    lab.ingress_request(request_id="notebook:attacks"), now=lab.NOW, step=0,
)
proposal = lab.translation_for(g, start.grant, lab.Protocol.A2A)
attacks = {
    "scope-widening": replace(
        proposal,
        authority=frozenset({"case.read", "records.export"}),
        protocol_scopes=frozenset({"a2a:task:create", "a2a:records:export"}),
    ),
    "audience-confusion": replace(
        proposal, target_audience="https://records.example.test/api"
    ),
    "credential-forwarding": replace(
        proposal, forwarded_credential="synthetic-inbound-token-42"
    ),
}
for index, (name, candidate) in enumerate(attacks.items(), start=1):
    decision = g.translate(p["supervisor"], candidate, now=lab.NOW, step=index)
    print(name, decision.state.value, decision.reason)
    assert not decision.allowed

skip = replace(
    proposal,
    translation_id="notebook:skip",
    to_protocol=lab.Protocol.MCP,
    target_audience="https://mcp.example.test/support",
    protocol_version=lab.MCP_PROTOCOL_VERSION,
    protocol_scopes=frozenset({"mcp:tools:call:lookup_case"}),
)
skipped = g.translate(p["supervisor"], skip, now=lab.NOW, step=5)
print("hop-skip", skipped.state.value, skipped.reason)
assert skipped.reason == "protocol-transition"
""",
        ),
        markdown(
            "a05-evidence-heading",
            """
## 9. Admit hostile evidence, then release a bounded field

The synthetic API response contains a legitimate summary and a malicious
instruction. Provenance admission binds source, version, producer, locator,
digest, tenant, resource, trace, and full grant lineage. Release returns only
the policy-approved summary.
""",
        ),
        code(
            "a05-evidence",
            """
released = sdk.admit_and_release(context)
artifact = context.result.artifact
print({
    "taint": sorted(artifact.taint),
    "summary": artifact.summary,
    "released": released.summary,
    "lineage_receipts": artifact.lineage_receipts,
})
assert "untrusted-content" in artifact.taint
assert released.summary == "Replacement shipment is approved."
assert "export" not in released.summary.lower()
""",
        ),
        markdown(
            "a05-failure-heading",
            """
## 10. Fail explicitly when token exchange is unavailable

An unavailable dependency produces an observable error. The gateway never
falls back to forwarding the inbound bearer credential or manufacturing a
downstream success.
""",
        ),
        code(
            "a05-failure",
            """
g, p = lab.build_scenario()
start = g.start_request(
    p["user"], lab.token_for(p["user"]),
    lab.ingress_request(request_id="notebook:failure"), now=lab.NOW, step=0,
)
g.token_exchange_available = False
failure = g.translate(
    p["supervisor"], lab.translation_for(g, start.grant, lab.Protocol.A2A),
    now=lab.NOW, step=1,
)
print(failure.state.value, failure.reason)
assert failure.state is lab.DecisionState.ERROR
assert failure.reason == "token-exchange-unavailable"
""",
        ),
        markdown(
            "a05-evaluation-heading",
            """
## 11. Evaluate exact valid, attack, and failure populations

The report has explicit denominators: five valid flows, twelve composed
attacks, and three dependency failures. Zero attack success is meaningful only
alongside 100% valid completion and explicit failure behavior.
""",
        ),
        code(
            "a05-evaluation",
            """
report, cases = lab.evaluate_controls()
print(asdict(report))
print({category: sum(case.category == category for case in cases)
       for category in ("valid", "attack", "failure")})
assert (report.valid_cases, report.attack_cases, report.failure_cases) == (5, 12, 3)
assert report.valid_completion_rate == 1.0
assert report.composed_attack_success_rate == 0.0
assert report.failure_error_rate == 1.0
""",
        ),
        markdown(
            "a05-production",
            """
## Production upgrade

Replace the deterministic teaching stores with transactional policy, identity,
replay, provenance, and ledger services. Use RFC 8693 token exchange with RFC
8707 resource indicators, sender-constrained tokens where appropriate, issuer
validation, a vetted outbound connector, durable exact-once semantics, and
alerts for rejected transitions, audience mismatch, replay mutation, missing
lineage, and dependency failure. Keep protocol SDK upgrades behind the same
application-owned invariants and conformance tests.

## Checkpoint

Can two individually secure protocols compose securely if authenticated user
identity becomes an unverified string between them? **No.** The next boundary
must authenticate the translator, preserve server-owned identity and resource
state, reauthorize the exact operation, and exchange authority for the new
audience. A typed message, task ID, trace header, or model statement is not an
authorization grant.
""",
        ),
    ]
    return notebook


def main() -> None:
    nbf.write(build_notebook(), OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
