# AI Agent Security Engineering expansion roadmap

This map defines the next 36-course learning path. Course numbers restart at
`01` within each level; the Learning Hub prefixes them with `F`, `I`, `A`, or
`E` when a globally unique label is useful. The currently published twelve-course
path remains listed in the repository root and Learning Hub while the remaining
topics pass their delivery gates. The expansion follows one
enterprise research-and-support scenario: an apparently helpful agent gains
RAG, memory, tool access, a specialist, MCP, durable state, and eventually
production authority. Each stage adds a trust boundary and an attack that must
be traced, contained, tested, and operationally owned.

## Foundation sequence (three published, four reading)

| Course | Focus | Practical artifact |
| --- | --- | --- |
| [01](roadmap/beginner/01-agent-security-architecture-and-trust-boundaries/) **Published** | architecture and boundaries | observable boundary inventory, executable controls, OpenTelemetry adapter, notebook, and tests |
| [02](roadmap/beginner/02-threat-modeling-agentic-systems/) **Published** | STRIDE, attack trees, abuse paths | evidence-bound threat records, pytm adapter, notebook, and tests |
| [03](roadmap/beginner/03-security-invariants-and-blast-radius/) **Published** | measurable safety properties | invariant engine, Hypothesis properties, notebook, and tests |
| [04](roadmap/beginner/04-secure-tool-and-action-interface-design/) | narrow typed tools | tool contract |
| [05](roadmap/beginner/05-authorization-approval-and-least-privilege/) | deterministic authorization | bound approval receipt |
| [06](roadmap/beginner/06-prompt-injection-and-untrusted-content/) | injection containment | attack matrix |
| [07](roadmap/beginner/07-context-and-evidence-security/) | provenance-aware context | context admission trace |

These chapters establish the conceptual sequence. Foundation 01–03 have passed
the publication gate. The remaining chapters are not labelled as published Hub
lessons until each owns or deliberately shares a reusable lab, adds a
top-to-bottom executable notebook, and receives a focused checkpoint.

## Intermediate sequence (pilot labs and planned topics)

| Course | Focus |
| --- | --- |
| [01](roadmap/intermediate/01-agent-memory-security/) | agent memory security |
| [02](roadmap/intermediate/02-state-checkpoint-and-durable-execution-security/) | durable state and checkpoints |
| [03](roadmap/intermediate/03-agent-identity-and-delegated-authority/) | identity and delegated authority |
| [04](roadmap/intermediate/04-secrets-and-credential-security/) | secrets and credentials |
| [05](roadmap/intermediate/05-filesystem-code-execution-and-sandbox-security/) | filesystem, execution, and sandboxing |
| [06](roadmap/intermediate/06-network-egress-ssrf-and-external-resource-security/) | egress, SSRF, and external resources |
| [07](roadmap/intermediate/07-tool-result-and-output-poisoning/) | tool-result and output poisoning |
| [08](roadmap/intermediate/08-agentic-rag-security/) | agentic RAG security |
| [09](roadmap/intermediate/09-mcp-security/) | MCP security |
| [10](roadmap/intermediate/10-human-in-the-loop-security/) | human-in-the-loop security |

## Advanced sequence (pilot labs and planned topics)

| Course | Focus |
| --- | --- |
| [01](roadmap/advanced/01-multi-agent-delegation-security/) | multi-agent delegation |
| [02](roadmap/advanced/02-cross-agent-prompt-injection-and-message-poisoning/) | cross-agent injection and message poisoning |
| [03](roadmap/advanced/03-cascading-failures-and-blast-radius-control/) | cascading failures and blast-radius control |
| [04](roadmap/advanced/04-agent-to-agent-a2a-security/) | agent-to-agent (A2A) security |
| [05](roadmap/advanced/05-protocol-composition-security/) | protocol composition security |
| [06](roadmap/advanced/06-agent-supply-chain-security/) | agent supply-chain security |
| [07](roadmap/advanced/07-agent-security-testing-and-fuzzing/) | security testing and fuzzing |
| [08](roadmap/advanced/08-agent-red-teaming-and-adversarial-evaluation/) | red teaming and adversarial evaluation |
| [09](roadmap/advanced/09-agent-security-observability-and-runtime-assurance/) | observability and runtime assurance |
| [10](roadmap/advanced/10-threat-hunting-and-behavioral-anomaly-detection/) | threat hunting and anomaly detection |

## Production / enterprise sequence (pilot labs and planned topics)

| Course | Focus |
| --- | --- |
| [01](roadmap/enterprise/01-secure-long-running-agents/) | secure long-running agents |
| [02](roadmap/enterprise/02-kill-switches-revocation-and-safe-degradation/) | kill switches, revocation, and safe degradation |
| [03](roadmap/enterprise/03-agent-incident-detection-and-containment/) | incident detection and containment |
| [04](roadmap/enterprise/04-agent-forensics-recovery-and-safe-replay/) | forensics, recovery, and safe replay |
| [05](roadmap/enterprise/05-security-release-gates-and-production-readiness/) | release gates and production readiness |
| [06](roadmap/enterprise/06-agent-security-governance/) | agent security governance |
| [07](roadmap/enterprise/07-enterprise-agent-security-architecture/) | enterprise security architecture |
| [08](roadmap/enterprise/08-agent-security-architecture-review-workshop/) | architecture review workshop |
| [09](roadmap/enterprise/09-production-secure-agent-capstone/) | production secure-agent capstone |

The Learning Hub is the authoritative status view. Each course page states its
current Reading, Pilot, or Planned status and the artifacts still required for
promotion.

## Shared lab

Run from the repository root:

```bash
python curriculum/shared/foundation_lab.py
python curriculum/shared/runtime_security_lab.py
```

The output is a deliberately limited trace with source provenance and policy
receipts. It does not expose private model reasoning.

The runtime lab adds delegation attenuation, resolved-address egress checks,
checkpoint resume checks, idempotent effects, revocation, and release-gate
evidence. It is a shared pilot baseline for several courses; sharing it does not
by itself make a roadmap topic complete.
