# AI Agent Security Engineering expansion roadmap

This numbered map defines the next 36-course learning path. The currently
published nine-course path remains listed in the repository root and Learning
Hub while these topics pass their delivery gates. The expansion follows one
enterprise research-and-support scenario: an apparently helpful agent gains
RAG, memory, tool access, a specialist, MCP, durable state, and eventually
production authority. Each stage adds a trust boundary and an attack that must
be traced, contained, tested, and operationally owned.

## Foundation sequence (reading sequence)

| Course | Focus | Practical artifact |
| --- | --- | --- |
| [01](beginner/01-agent-security-architecture-and-trust-boundaries/) | architecture and boundaries | observable boundary inventory |
| [02](beginner/02-threat-modeling-agentic-systems/) | STRIDE, attack trees, abuse paths | threat record |
| [03](beginner/03-security-invariants-and-blast-radius/) | measurable safety properties | invariant suite |
| [04](beginner/04-secure-tool-and-action-interface-design/) | narrow typed tools | tool contract |
| [05](beginner/05-authorization-approval-and-least-privilege/) | deterministic authorization | bound approval receipt |
| [06](beginner/06-prompt-injection-and-untrusted-content/) | injection containment | attack matrix |
| [07](beginner/07-context-and-evidence-security/) | provenance-aware context | context admission trace |

These chapters establish the conceptual sequence. They are not labelled as
published Hub lessons until each owns or deliberately shares a reusable lab,
adds a top-to-bottom executable notebook, and receives a focused checkpoint.

## Intermediate sequence (pilot labs and planned topics)

[08 Memory](intermediate/08-agent-memory-security/) · [09 Durable state](intermediate/09-state-checkpoint-and-durable-execution-security/) · [10 Identity](intermediate/10-agent-identity-and-delegated-authority/) · [11 Secrets](intermediate/11-secrets-and-credential-security/) · [12 Sandbox](intermediate/12-filesystem-code-execution-and-sandbox-security/) · [13 Egress](intermediate/13-network-egress-ssrf-and-external-resource-security/) · [14 Tool output](intermediate/14-tool-result-and-output-poisoning/) · [15 RAG](intermediate/15-agentic-rag-security/) · [16 MCP](intermediate/16-mcp-security/) · [17 Human approval](intermediate/17-human-in-the-loop-security/)

## Advanced sequence (pilot labs and planned topics)

[18 Delegation](advanced/18-multi-agent-delegation-security/) · [19 Cross-agent injection](advanced/19-cross-agent-prompt-injection-and-message-poisoning/) · [20 Cascades](advanced/20-cascading-failures-and-blast-radius-control/) · [21 A2A](advanced/21-agent-to-agent-a2a-security/) · [22 Composition](advanced/22-protocol-composition-security/) · [23 Supply chain](advanced/23-agent-supply-chain-security/) · [24 Fuzzing](advanced/24-agent-security-testing-and-fuzzing/) · [25 Red teaming](advanced/25-agent-red-teaming-and-adversarial-evaluation/) · [26 Observability](advanced/26-agent-security-observability-and-runtime-assurance/) · [27 Hunting](advanced/27-threat-hunting-and-behavioral-anomaly-detection/)

## Production / enterprise sequence (pilot labs and planned topics)

[28 Long-running agents](enterprise-agent/28-secure-long-running-agents/) · [29 Kill switches](enterprise-agent/29-kill-switches-revocation-and-safe-degradation/) · [30 Containment](enterprise-agent/30-agent-incident-detection-and-containment/) · [31 Forensics](enterprise-agent/31-agent-forensics-recovery-and-safe-replay/) · [32 Release gates](enterprise-agent/32-security-release-gates-and-production-readiness/) · [33 Governance](enterprise-agent/33-agent-security-governance/) · [34 Enterprise architecture](enterprise-agent/34-enterprise-agent-security-architecture/) · [35 Review workshop](enterprise-agent/35-agent-security-architecture-review-workshop/) · [36 Capstone](enterprise-agent/36-production-secure-agent-capstone/)

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
