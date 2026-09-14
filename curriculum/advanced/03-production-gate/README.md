# Advanced 03 — Governance and Production Readiness

## Capability

Issue an evidence-based production decision that rejects missing, empty, stale,
failed, duplicate, or ownerless evidence and treats severe attack successes as
non-negotiable blockers.

## Learning outcomes

You will be able to define a typed release dossier, validate evidence freshness
and ownership, separate residual-risk acceptance from control evidence, block
severe failures, and emit a reproducible decision receipt.

Prerequisite: [Advanced 02 — Multi-Agent Delegation](../02-multi-agent-security/README.md).

Next: [36-course enterprise roadmap](../../README.md).

## Governing invariant

> Production authority is granted by a trusted release process from valid
> evidence. A demo, average score, model recommendation, or file’s existence is
> not production evidence.

## Evidence contract

The lab requires a threat model, policy tests, attack evaluation, trace
coverage, rollback drill, and control owner. Every `Evidence` item has a
non-empty value, version, owner, observation time, and pass/fail result.

```text
threat model ─────┐
policy tests ─────┤
attack evaluation ┤
trace coverage ───┼─> trusted release gate ─> decision + blockers + receipt
rollback drill ───┤
control owner ────┘          ▲
                     named, expiring risk acceptance
```

Residual risk is not hidden inside a score. It is a separate, named,
time-bounded acceptance with rationale and an accountable owner. A severe
unauthorized action blocks the release even if every required document exists.

## Practical lab

```bash
python3 curriculum/advanced/03-production-gate/03_production_gate.py
jupyter notebook curriculum/advanced/03-production-gate/03_production_gate.ipynb
```

The notebook builds a valid dossier, then injects five realistic failures:
empty evidence, stale evidence, a failed rollback drill, an expired risk
acceptance, and a severe attack success. Each produces an explicit blocker.

### Review questions

- Does each artifact identify the exact release or policy version it covers?
- Was evidence produced by an independent or appropriately trusted component?
- Can a reviewer follow the receipt to tests and operational records?
- Does the rollback drill prove people and systems can act under pressure?
- Are severe cases visible individually rather than averaged away?
- Are residual risks named, owned, time-bounded, and reviewable?

## Production operating model

Treat the gate as policy-as-code around a human-accountable change process.
Store evidence in access-controlled, durable systems; authenticate producers;
protect history; and enforce branch and environment protections outside the
agent. Connect the decision to deployment, staged rollout, monitoring,
rollback, kill switches, and incident ownership.

Measure severe failures, attack success by family, valid-task blocking, trace
coverage, rollback success and time, evidence age, exception count, overdue
risk acceptances, and post-release incidents. Do not collapse these into one
weighted number.

Residual risks include flawed test coverage, compromised evidence producers,
production drift, delayed revocation, organizational pressure, and untested
interactions between controls. Continuous monitoring and periodic reapproval
remain necessary after launch.

## Checkpoint

All six required evidence files exist, but the rollback drill is empty and the
attack suite recorded one critical unauthorized action. Is the agent ready?

- A. Yes, because every required filename exists.
- B. No, because evidence must be valid and the severe failure is a blocker.
- C. Yes, if a risk score averages above 80%.

**Answer: B.** Presence-only checks create false assurance. Trusted code must
validate the evidence and preserve non-averaged severe blockers.

## References

- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI RMF Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook)
- [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
