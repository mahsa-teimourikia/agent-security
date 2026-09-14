# 08 — Agent Security Architecture Review Workshop

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Find, prioritize, prove, and remediate agent-system security gaps using a repeatable evidence rubric.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `finding precision, severe-gap recall, remediation quality, and reviewer agreement`, and explain what remains for production.

## Enterprise scenario

A review team receives a flawed multi-tenant support-agent design packet before launch.

### Primary attack

A diagram-only review misses authority flows, indirect resources, failure modes, operational owners, and untested recovery.

### Governing control and invariant

Reviewers trace assets, actors, boundaries, abuse paths, invariants, controls, evidence, owners, and residual risk to concrete findings.

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

Primary evaluation: **finding precision, severe-gap recall, remediation quality, and reviewer agreement**. Report denominators and severe cases
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

What separates an actionable finding from a generic recommendation?

**Expected reasoning:** It names the violated invariant, attack path, affected asset, evidence, severity, owner, and verifiable remediation.

## Reference baseline

- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
