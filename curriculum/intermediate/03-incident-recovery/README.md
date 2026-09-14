# Intermediate 03 — Agent Incident Response and Recovery

## Capability

Contain a suspicious agent run, preserve a useful chronology, reauthorize a
known checkpoint, and replay an external effect exactly once.

## Learning outcomes

After this course, you can:

1. distinguish detection, containment, recovery planning, authorization, and
   replay as separate control decisions;
2. revoke capabilities before investigating or resuming a run;
3. validate checkpoint integrity plus policy and credential freshness;
4. require an independent operator for recovery; and
5. verify a tamper-evident event chain and idempotent effects.

Prerequisite: [Intermediate 02 — MCP Gateway Security](../02-mcp-gateway/README.md).

Next: [Advanced 01 — Security Attack Evaluation](../../advanced/01-attack-evaluation/README.md).

## Governing invariant

> Detection never grants recovery. A contained run may regain an external
> capability only after trusted code validates state, current policy,
> credentials, independent approval, and an idempotency key.

## Scenario and threat model

A support agent tries to send connector data to an unexpected destination.
The egress monitor detects the signal, but the run already has durable state
and a pending ticket update. An attacker may influence saved model output,
the recovery proposal, or a replay request. They must not be able to approve
their own plan, restore stale authority, alter the checkpoint, or duplicate
the external effect.

```text
active ──signal──> detected ──revoke/isolate──> contained
                                                   │
                                           recovery proposal
                                                   ▼
                                          recovery_pending
                                                   │
                           independent validation + authorization
                                                   ▼
                                               recovered
                                                   │
                                       idempotent external effect
```

The phase transitions are deliberately fail-closed. `commit_once` cannot run
while active, merely detected, contained, or awaiting approval. Recovery also
requires the plan’s checkpoint digest, policy version, and credential version
to match trusted current state.

## Practical lab

Run from the repository root:

```bash
python3 curriculum/intermediate/03-incident-recovery/03_incident_recovery.py
jupyter notebook curriculum/intermediate/03-incident-recovery/03_incident_recovery.ipynb
```

The lab creates a canonical checkpoint digest, records detection and
containment, proposes recovery, denies invalid recovery variants, approves a
valid plan, and proves that a retry cannot commit the effect twice.

### Failure injections

| Failure | Expected control |
| --- | --- |
| resume before containment | phase transition rejects it |
| missing revocation target | containment rejects it |
| model/automation approves its own plan | independent approver check denies it |
| checkpoint state changes | digest comparison denies recovery |
| policy or credential version is stale | freshness checks deny recovery |
| external request is retried | idempotency key blocks the second effect |
| event chronology is edited | hash-chain verification fails |

## Observable evidence

The lab records sequence, event kind, bounded detail, actor, time, prior hash,
and event hash. A production system also needs authenticated actor identity,
durable append-only storage, access control, retention, clock assurance, and
redaction. A Python hash chain demonstrates tamper evidence; it is not a
substitute for a protected audit service.

Useful metrics include mean time to contain, revocation propagation latency,
percentage of runs with complete event chains, recovery denial reasons,
duplicate-effect count, and successful rollback-drill rate. Averages must not
hide a severe unauthorized effect.

## Production considerations and residual risk

Coordinate model/API shutdown, connector and credential revocation, egress
isolation, evidence preservation, affected-user handling, and ownership.
Assume partial failures: a connector may be unreachable, a worker may have an
old lease, or a queue may redeliver. Test those conditions explicitly.

Residual risk includes compromised responders, delayed revocation, incomplete
telemetry, side effects without provider idempotency, and tampering outside the
audited boundary. The enterprise roadmap courses 29–31 deepen these controls.

## Checkpoint

A valid checkpoint was created yesterday, but policy and connector credentials
changed after an incident. May the agent resume from that checkpoint?

- A. Yes, because its digest is valid.
- B. Yes, if the model says the task is unchanged.
- C. No; trusted code must revalidate current policy, credentials, intent, and
  approval before restoring capability.

**Answer: C.** Integrity proves what the checkpoint contains, not that its old
authority remains valid now.

## References

- [NIST Computer Security Incident Handling Guide SP 800-61 Rev. 2](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
