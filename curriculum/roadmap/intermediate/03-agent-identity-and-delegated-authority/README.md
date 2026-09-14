# 03 — Agent Identity and Delegated Authority

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Preserve the authenticated human and workload chain while reducing authority at every service hop.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `scope-escalation success and identity-chain trace coverage`, and explain what remains for production.

## Enterprise scenario

A support orchestrator delegates document lookup to a specialist and storage service.

### Primary attack

A model-controlled subject, tenant, or audience creates a confused deputy and cross-tenant read.

### Governing control and invariant

The application issues short-lived, audience-bound grants whose operation and resource sets can only shrink.

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

Primary evaluation: **scope-escalation success and identity-chain trace coverage**. Report denominators and severe cases
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

A token valid for service A is presented to service B. Why must B reject it?

**Expected reasoning:** Audience validation prevents a credential from becoming ambient authority at another service.

## Reference baseline

- [RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693.html)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
