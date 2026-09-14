# 27 — Threat Hunting and Behavioral Anomaly Detection

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Turn observable agent trajectories into explainable hypotheses and evaluate detectors against labeled events.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `precision, recall, time to detect, alert volume, and tenant-normalized false positives`, and explain what remains for production.

## Enterprise scenario

A defender analyzes tenant-scoped sequences of retrieval, delegation, tool use, denial, and egress.

### Primary attack

Slow scope probing, unusual fan-out, repeated approval failures, or destination drift evade single-event alerts.

### Governing control and invariant

Deterministic sequence features and rules produce evidence-linked alerts that analysts can validate and tune.

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

Primary evaluation: **precision, recall, time to detect, alert volume, and tenant-normalized false positives**. Report denominators and severe cases
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

Why is an opaque anomaly score insufficient for a security response?

**Expected reasoning:** Responders need the events and rule evidence that justify containment and support tuning.

## Reference baseline

- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
