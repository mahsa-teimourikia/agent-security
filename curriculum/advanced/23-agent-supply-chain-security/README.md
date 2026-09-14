# 23 — Agent Supply-Chain Security

<!-- roadmap-status -->
> **Roadmap status: Planned.** The release contract is defined; lab, notebook, tests, and checkpoint are still required.

## Capability

Inventory and verify the source, version, integrity, privileges, and rollback path of every agent component.

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `verified-artifact coverage, unpinned components, provenance failures, and rollback time`, and explain what remains for production.

## Enterprise scenario

A platform updates prompts, model packages, plugins, MCP servers, container images, and policy bundles.

### Primary attack

Dependency substitution, malicious updates, mutable tags, poisoned prompts, or downgraded policy enter the runtime.

### Governing control and invariant

Pinned identities and digests, signed provenance, protected review, least-privilege manifests, staged rollout, and rollback guard consumption.

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

Primary evaluation: **verified-artifact coverage, unpinned components, provenance failures, and rollback time**. Report denominators and severe cases
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

Does the presence of provenance prove an artifact is acceptable?

**Expected reasoning:** No. A trusted verifier must validate it against expected source, builder, digest, and policy.

## Reference baseline

- [SLSA 1.2](https://slsa.dev/spec/v1.2/)
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
