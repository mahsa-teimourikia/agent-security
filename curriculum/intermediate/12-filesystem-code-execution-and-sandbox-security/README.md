# 12 — Filesystem, Code Execution, and Sandbox Security

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Constrain generated code with an external execution boundary that enforces filesystem, network, syscall, time, and resource policy.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `escape success, forbidden-read rate, resource-limit enforcement, and valid-job completion`, and explain what remains for production.

## Enterprise scenario

A coding agent analyzes an uploaded archive and generates a report.

### Primary attack

Path traversal, symlink escape, fork/resource exhaustion, and unexpected network access escape the task boundary.

### Governing control and invariant

A trusted sandbox broker mounts a disposable workspace, denies ambient credentials and network, applies resource limits, and destroys the environment.

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

Primary evaluation: **escape success, forbidden-read rate, resource-limit enforcement, and valid-job completion**. Report denominators and severe cases
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

Why is asking the model to avoid dangerous shell commands not a sandbox?

**Expected reasoning:** The model is inside the threat boundary; only an independently enforced runtime can constrain execution.

## Reference baseline

- [NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
