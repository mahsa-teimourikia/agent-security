# 26 — Agent Security Observability and Runtime Assurance

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Reconstruct who authorized what action from which evidence and policy without collecting secrets or private reasoning.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `attribution and decision coverage, redaction failures, orphan effects, and detection latency`, and explain what remains for production.

## Enterprise scenario

A production support agent retrieves evidence, delegates, calls tools, pauses, and resumes.

### Primary attack

Missing correlation hides unsafe actions while over-collection leaks prompts, tokens, personal data, or confidential tool results.

### Governing control and invariant

A versioned trace schema records identities, boundaries, hashes, decisions, state transitions, and effects with redaction and access policy.

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

Primary evaluation: **attribution and decision coverage, redaction failures, orphan effects, and detection latency**. Report denominators and severe cases
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

Should observability store raw access tokens to make incidents easier to investigate?

**Expected reasoning:** No. Record safe identifiers and fingerprints; telemetry itself is a sensitive data system.

## Reference baseline

- [OpenTelemetry sensitive-data guidance](https://opentelemetry.io/docs/security/handling-sensitive-data/)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
