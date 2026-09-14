# 08 — Agentic RAG Security

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Retrieve only authorized, attributable, fresh evidence and evaluate both leakage and grounding before it reaches an agent.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `cross-tenant leakage, poisoned-chunk admission, citation precision, and blocked-valid-query rate`, and explain what remains for production.

## Enterprise scenario

A multi-tenant policy assistant retrieves internal and external knowledge.

### Primary attack

Poisoned chunks, cross-tenant retrieval, metadata leakage, and citation laundering turn retrieval into an attack path.

### Governing control and invariant

Authorization-aware retrieval filters at the datastore, binds provenance and sensitivity, isolates instructions from evidence, and validates citations.

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

Primary evaluation: **cross-tenant leakage, poisoned-chunk admission, citation precision, and blocked-valid-query rate**. Report denominators and severe cases
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

Can a post-generation instruction repair a secret that was already retrieved into model context?

**Expected reasoning:** No. Access control and minimization must prevent unauthorized content from entering context in the first place.

## Reference baseline

- [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
