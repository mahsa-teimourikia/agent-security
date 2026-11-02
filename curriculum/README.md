# AI Agent Security Engineering expansion roadmap

This map defines the next 36-course learning path. Course numbers restart at
`01` within each level; the Learning Hub prefixes them with `F`, `I`, `A`, or
`E` when a globally unique label is useful. The currently published course
catalog remains listed in the repository root and Learning Hub while the remaining
topics pass their delivery gates. The expansion follows one
enterprise research-and-support scenario: an apparently helpful agent gains
RAG, memory, tool access, a specialist, MCP, durable state, and eventually
production authority. Each stage adds a trust boundary and an attack that must
be traced, contained, tested, and operationally owned.

## Foundation sequence (seven published)

| Course | Focus | Practical artifact |
| --- | --- | --- |
| [01](roadmap/beginner/01-agent-security-architecture-and-trust-boundaries/) **Published** | architecture and boundaries | observable boundary inventory, executable controls, OpenTelemetry adapter, notebook, and tests |
| [02](roadmap/beginner/02-threat-modeling-agentic-systems/) **Published** | STRIDE, attack trees, abuse paths | evidence-bound threat records, pytm adapter, notebook, and tests |
| [03](roadmap/beginner/03-security-invariants-and-blast-radius/) **Published** | measurable safety properties | invariant engine, Hypothesis properties, notebook, and tests |
| [04](roadmap/beginner/04-secure-tool-and-action-interface-design/) **Published** | narrow typed tools | versioned gateway, SDK adapter, recovery lab, notebook, and tests |
| [05](roadmap/beginner/05-authorization-approval-and-least-privilege/) **Published** | deterministic authorization | PDP/PEP, least-privilege derivation, exact approval, SDK adapter, notebook, and tests |
| [06](roadmap/beginner/06-prompt-injection-and-untrusted-content/) **Published** | injection containment | typed containment gateway, SDK adapter, attack matrix, notebook, and tests |
| [07](roadmap/beginner/07-context-and-evidence-security/) **Published** | provenance-aware context | context compiler, evidence verifier, SDK adapter, notebook, and tests |

These chapters establish the conceptual sequence. Foundation 01–07 have passed
the publication gate: each owns a reusable lab, top-to-bottom executable
notebook, focused tests, and a Learning Hub checkpoint.

## Intermediate sequence (ten published topics)

| Course | Focus |
| --- | --- |
| [01](roadmap/intermediate/01-agent-memory-security/) **Published** | secure long-term memory lifecycle, consent, versioning, deletion, SDK adapter, notebook, and tests |
| [02](roadmap/intermediate/02-state-checkpoint-and-durable-execution-security/) **Published** | secure checkpoint chains, current resume authorization, deterministic migration, exclusive leases, uncertain-effect reconciliation, SDK adapter, notebook, and tests |
| [03](roadmap/intermediate/03-agent-identity-and-delegated-authority/) **Published** | distinct human, agent, and workload identity; sender-bound per-hop delegation; current lifecycle enforcement; SDK adapter; notebook; diagram; and tests |
| [04](roadmap/intermediate/04-secrets-and-credential-security/) **Published** | credential isolation, one-use version-bound leases, rotation and replay controls, SDK adapter, notebook, diagram, and tests |
| [05](roadmap/intermediate/05-filesystem-code-execution-and-sandbox-security/) **Published** | archive admission, one-use execution grants, filesystem/network/syscall/resource enforcement, SDK adapter, notebook, diagram, and tests |
| [06](roadmap/intermediate/06-network-egress-ssrf-and-external-resource-security/) **Published** | canonical URL admission, all-answer DNS policy, one-use fetch grants, connection authority, per-hop redirects, bounded responses, SDK/HTTPX adapter, notebook, diagram, and tests |
| [07](roadmap/intermediate/07-tool-result-and-output-poisoning/) **Published** | evidence admission, hostile-prose containment, independent action authorization, safe output reconstruction, SDK adapter, notebook, diagram, and tests |
| [08](roadmap/intermediate/08-agentic-rag-security/) **Published** | authorization-before-ranking, source/chunk lineage, poison containment, conflict-aware claim release, Pydantic/OpenTelemetry adapter, notebook, diagram, and tests |
| [09](roadmap/intermediate/09-mcp-security/) **Published** | modern MCP discovery and catalog pinning, authenticated connection identity, exact call grants, credential isolation, result admission, MCP Python SDK v2 adapter, notebook, diagram, and tests |
| [10](roadmap/intermediate/10-human-in-the-loop-security/) **Published** | durable human review state, tenant-scoped queues, reviewer independence and quorum, exact one-use grants, resume reauthorization, ambiguous-outcome reconciliation, OpenAI Agents SDK adapter, notebook, diagram, and tests |

## Advanced sequence (eight published and two planned topics)

| Course | Focus |
| --- | --- |
| [01](advanced/02-multi-agent-security/) **Published** | authenticated multi-agent delegation, authority attenuation, current policy and revocation, registry-backed result provenance, OpenAI Agents SDK adapter, notebook, diagram, and tests |
| [02](roadmap/advanced/02-cross-agent-prompt-injection-and-message-poisoning/) **Published** | authenticated peer-message admission, source lineage, taint-preserving transformation, independent effect authorization, OpenAI Agents SDK adapter, notebook, diagram, and tests |
| [03](roadmap/advanced/03-cascading-failures-and-blast-radius-control/) **Published** | shared cascade budgets, centralized transient-only retries, queue bulkheads, circuit isolation, poison containment, idempotent effects, OpenAI Agents SDK adapter, notebook, diagram, and tests |
| [04](roadmap/advanced/04-agent-to-agent-a2a-security/) **Published** | Agent Card admission, local skill grants, per-operation task authorization, artifact containment, callback SSRF controls, official A2A Python SDK adapter, notebook, diagram, and tests |
| [05](roadmap/advanced/05-protocol-composition-security/) **Published** | identity- and authority-preserving web/A2A/MCP/API translation, audience-bound grants, hop ledger, provenance admission, official A2A/MCP/HTTPX adapter, notebook, diagram, and tests |
| [06](roadmap/advanced/06-agent-supply-chain-security/) **Published** | signed SLSA/in-toto provenance, immutable artifacts and dependencies, least-privilege manifests, CycloneDX inventory, risk evidence, Sigstore adapter, staged rollout, one-use rollback, notebook, diagram, and tests |
| [07](roadmap/advanced/07-agent-security-testing-and-fuzzing/) **Published** | application-owned security oracles, labelled valid/attack/boundary/failure corpora, Hypothesis properties and state machines, semantic shrinking, replay and race testing, notebook, diagram, and tests |
| [08](roadmap/advanced/08-agent-red-teaming-and-adversarial-evaluation/) **Published** | version-bound red-team campaigns, independent effect verification, PyRIT adapter, disjoint security/utility metrics, finding regressions, notebook, diagram, and tests |
| [09](roadmap/advanced/09-agent-security-observability-and-runtime-assurance/) **Published** | authoritative event admission, privacy minimization, trace completeness, policy/effect/approval/budget monitors, explicit healthy/degraded/violated/unknown states, real OpenTelemetry Python SDK adapter, notebook, diagram, and tests |
| [10](roadmap/advanced/10-threat-hunting-and-behavioral-anomaly-detection/) | threat hunting and anomaly detection |

## Production / enterprise sequence (two published topics, pilots, and planned topics)

| Course | Focus |
| --- | --- |
| [01](roadmap/enterprise/01-secure-long-running-agents/) **Published** | checkpoint integrity vs current authority, short version-bound resume leases, one-owner fencing, heartbeat/orphan handling, unknown-effect reconciliation, OpenAI Agents SDK RunState bridge, notebook, diagram, and tests |
| [02](roadmap/enterprise/02-kill-switches-revocation-and-safe-degradation/) **Published** | independently operated signed control commands, monotonic epochs, scheduling/effect enforcement, stale-state denial, governed diagnostics, in-flight reconciliation, separately approved recovery, OpenFeature adapter, notebook, diagram, and tests |
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
