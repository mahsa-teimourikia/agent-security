# 07 — Agent Security Testing and Fuzzing

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Generate and minimize malformed actions, states, and protocol messages around explicit security invariants.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `invariant violations, unique failure families, minimized case size, and valid-case rejection`, and explain what remains for production.

## Enterprise scenario

A test harness exercises a typed action gateway and durable workflow state machine.

### Primary attack

Boundary encodings, missing fields, extreme sizes, illegal state transitions, and sequence races bypass example-based tests.

### Governing control and invariant

Deterministic generators create valid and adversarial cases; an oracle checks invariants and retains minimal reproducible failures.

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

Primary evaluation: **invariant violations, unique failure families, minimized case size, and valid-case rejection**. Report denominators and severe cases
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

What makes a fuzzer useful for security rather than merely noisy?

**Expected reasoning:** A trustworthy oracle tied to explicit invariants and reproducible minimized failures.

## Reference baseline

- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
