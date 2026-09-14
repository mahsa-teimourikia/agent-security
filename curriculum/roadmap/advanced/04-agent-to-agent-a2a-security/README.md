# 04 — Agent-to-Agent (A2A) Security

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Authenticate peers and authorize every task operation independently of Agent Card discovery.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `spoof/replay acceptance, unauthorized task access, callback SSRF, and audit coverage`, and explain what remains for production.

## Enterprise scenario

An enterprise agent delegates a research task to an external specialist over A2A 1.0.

### Primary attack

A spoofed card, replayed task, cross-tenant history query, malicious artifact, or callback SSRF crosses the peer boundary.

### Governing control and invariant

Verify transport and peer identity, validate cards and schemas, scope every task operation, bind idempotency, and validate callback destinations.

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

Primary evaluation: **spoof/replay acceptance, unauthorized task access, callback SSRF, and audit coverage**. Report denominators and severe cases
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

Does an Agent Card authorize the skills it advertises?

**Expected reasoning:** No. It is discovery metadata; the server must authenticate and authorize every operation.

## Reference baseline

- [A2A 1.0 specification](https://a2a-protocol.org/latest/specification/)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
