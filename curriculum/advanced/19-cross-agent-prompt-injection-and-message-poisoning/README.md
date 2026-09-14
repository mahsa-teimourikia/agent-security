# 19 — Cross-Agent Prompt Injection and Message Poisoning

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Preserve provenance and taint across handoffs so one compromised worker cannot turn content into authority downstream.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `poison propagation, provenance loss, unsafe follow-on proposals, and valid-handoff completion`, and explain what remains for production.

## Enterprise scenario

A researcher sends evidence to a writer, which proposes a customer-facing action.

### Primary attack

A poisoned source becomes a clean-looking summary and triggers a follow-on tool call.

### Governing control and invariant

Workers exchange typed artifacts with source IDs, trust labels, allowed uses, and decision receipts; consumers never treat prose as delegation.

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

Primary evaluation: **poison propagation, provenance loss, unsafe follow-on proposals, and valid-handoff completion**. Report denominators and severe cases
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

Does a summary produced by a trusted agent become trusted instructions?

**Expected reasoning:** No. Agent identity establishes attribution, not the authority or truth of the content it produced.

## Reference baseline

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
