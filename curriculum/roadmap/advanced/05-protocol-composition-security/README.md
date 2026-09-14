# 05 — Protocol Composition Security

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Carry identity, authority, provenance, correlation, and limits across UI, A2A, MCP, and downstream API hops.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `lost-identity rate, scope widening, correlation coverage, and composed attack success`, and explain what remains for production.

## Enterprise scenario

A user request crosses a web front door, supervisor, A2A specialist, MCP server, and records API.

### Primary attack

Each protocol is locally valid, but an audience, tenant, approval, or provenance binding disappears between hops.

### Governing control and invariant

A hop ledger records authenticated actor, delegate, audience, scopes, resource, evidence, policy decision, and correlation at every translation.

The model may propose. Trusted application or infrastructure code validates,
authorizes, persists, executes, and verifies. Structured content remains
untrusted until provenance and authorization are established.

## Required practical slice

The course will ship one credential-free `lab.py` and one top-to-bottom
notebook. The learner must first run a valid baseline, then inject the primary
attack, inspect a structured denial or containment receipt, attempt at least
one bypass, and rerun the same metric. Tests must cover safe behavior,
adversarial behavior, edge cases, and the governing invariant.

The teaching lab will use deterministic local fixtures. It must clearly name
the production replacement for every simulated boundary and must not claim
that Python object structure, a prompt, or a local hash is a production trust
mechanism.

## Evaluation and operations

Primary evaluation: **lost-identity rate, scope widening, correlation coverage, and composed attack success**. Report denominators and severe cases
separately from averages. The final course must also identify detection,
containment, recovery, evidence retention, and accountable owners. Residual
risk is documented rather than silently treated as eliminated.

## Failure injections to include

- a direct violation of the main trust boundary;
- an indirect or encoded variant that defeats a naive check;
- stale, replayed, missing, or cross-tenant state where applicable;
- a valid task that should remain usable; and
- an unavailable dependency or degraded-mode case.

## Checkpoint

Can two individually secure protocols compose securely if identity is converted to an unverified string between them?

**Expected reasoning:** No. Composition must preserve and revalidate the security invariants at every adapter.

## Reference baseline

- [MCP specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
