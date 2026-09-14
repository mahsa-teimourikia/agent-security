# Advanced 02 — Multi-Agent Delegation Security

## Capability

Issue and enforce a delegation envelope that attenuates a parent agent’s
identity, tenant, scope, budget, lifetime, and output contract.

## Learning outcomes

You will be able to distinguish delegation from role naming, prove child scope
is a subset of authenticated parent authority, enforce budgets and expiry at
execution time, preserve artifact provenance, and terminate a worker without
depending on its cooperation.

Prerequisite: [Advanced 01 — Attack Evaluation](../01-attack-evaluation/README.md).

Next: [Advanced 03 — Production Readiness](../03-production-gate/README.md).

## Governing invariant

> A child’s effective authority must always be a strict or equal subset of its
> authenticated parent’s authority, bounded by tenant, time, budget, and task.

## Threat model and architecture

The supervisor may be influenced by untrusted content and the worker may be
compromised. Attackers can request a different tenant, a wider operation, a
larger budget, a longer lifetime, or an unexpected artifact. The trusted
delegation service and execution boundary remain outside model control.

```text
authenticated parent authority
              │ requested child task
              ▼
      delegation policy service
      tenant · subset · TTL · budget · artifact types
              │ immutable envelope
              ▼
       worker execution boundary ──> typed, attributable artifact
              │
              └── decision receipts + independent termination
```

A role name such as “researcher” carries no authority by itself. The envelope
does. The lab intentionally uses a deterministic identifier rather than a real
signature. Production systems need an authenticated issuer, integrity
protection, rotation, revocation, and replay defense appropriate to their trust
boundary.

## Practical lab

```bash
python3 curriculum/advanced/02-multi-agent-security/02_multi_agent_security.py
jupyter notebook curriculum/advanced/02-multi-agent-security/02_multi_agent_security.ipynb
```

The safe supervisor delegates only `search`, one unit of budget, a ten-minute
lifetime, tenant `north`, and an `evidence-list` artifact. The worker succeeds
once. A second call exhausts the budget and an attempted `delete` delegation is
rejected before an envelope is issued.

### Bypass attempts

| Attempt | Enforced at | Expected result |
| --- | --- | --- |
| child requests scope absent from parent | issuance | no envelope |
| cross-tenant child | issuance and use | deny |
| excessive budget or lifetime | issuance | no envelope |
| different worker reuses envelope | use | deny |
| expired envelope | use | deny |
| wrong artifact type | use | deny |
| child continues after termination | use | deny |

## Evaluation and operations

Measure privilege-amplification success, cross-tenant success, replay success,
budget overrun, post-termination action count, artifact provenance coverage,
and blocked-valid-task rate. Trace parent, child, tenant, envelope identifier,
operation, artifact type, budget consumption, decision, reason, and time; do
not log secrets or private reasoning.

Real deployments also need workload identity, authenticated messaging,
revocation propagation, concurrency-safe budgets, depth and fan-out limits,
loop detection, egress controls, state isolation, and incident ownership.
Typed artifacts still contain untrusted data and must be validated by the next
consumer. Delegation controls authority; they do not make content true.

## Checkpoint

A supervisor can `search` and `read`. Its child asks for `search` and `delete`
because deletion would make the task faster. What may the delegation service
issue?

- A. Both operations because the child has a specialist role.
- B. Only a subset of the parent’s authority; the request as written fails.
- C. Any operation if the prompt records the reason.

**Answer: B.** Role labels and model explanations cannot widen authenticated
authority.

## References

- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [A2A Protocol specification](https://a2a-protocol.org/latest/specification/)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
