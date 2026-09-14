# 07 — Enterprise Agent Security Architecture

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Place independent policy, isolation, evidence, and operational controls at every authority-changing enterprise boundary.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `control and owner coverage, unmediated paths, single points of failure, and residual-risk closure`, and explain what remains for production.

## Enterprise scenario

A shared enterprise platform hosts RAG, memory, tools, MCP/A2A peers, durable workflows, and multiple tenants.

### Primary attack

Central credentials, implicit trust, shared state, uncontrolled egress, or missing ownership lets one compromise cross domains.

### Governing control and invariant

A reference architecture maps identity, context, model, action, execution, state, protocol, telemetry, and response controls to owners.

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

Primary evaluation: **control and owner coverage, unmediated paths, single points of failure, and residual-risk closure**. Report denominators and severe cases
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

Where should authorization live in an enterprise agent platform?

**Expected reasoning:** At every protected resource and action boundary, supported by shared policy services—not inside prompts alone.

## Reference baseline

- [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
