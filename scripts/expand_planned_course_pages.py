"""Generate substantive, explicitly planned pages for roadmap-only courses."""
from pathlib import Path


COURSES = [
    ("curriculum/intermediate/10-agent-identity-and-delegated-authority", "10 — Agent Identity and Delegated Authority", "Preserve the authenticated human and workload chain while reducing authority at every service hop.", "A support orchestrator delegates document lookup to a specialist and storage service.", "A model-controlled subject, tenant, or audience creates a confused deputy and cross-tenant read.", "The application issues short-lived, audience-bound grants whose operation and resource sets can only shrink.", "scope-escalation success and identity-chain trace coverage", "A token valid for service A is presented to service B. Why must B reject it?", "Audience validation prevents a credential from becoming ambient authority at another service.", "[RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693.html)"),
    ("curriculum/intermediate/12-filesystem-code-execution-and-sandbox-security", "12 — Filesystem, Code Execution, and Sandbox Security", "Constrain generated code with an external execution boundary that enforces filesystem, network, syscall, time, and resource policy.", "A coding agent analyzes an uploaded archive and generates a report.", "Path traversal, symlink escape, fork/resource exhaustion, and unexpected network access escape the task boundary.", "A trusted sandbox broker mounts a disposable workspace, denies ambient credentials and network, applies resource limits, and destroys the environment.", "escape success, forbidden-read rate, resource-limit enforcement, and valid-job completion", "Why is asking the model to avoid dangerous shell commands not a sandbox?", "The model is inside the threat boundary; only an independently enforced runtime can constrain execution.", "[NIST SP 800-190](https://csrc.nist.gov/pubs/sp/800/190/final)"),
    ("curriculum/intermediate/15-agentic-rag-security", "15 — Agentic RAG Security", "Retrieve only authorized, attributable, fresh evidence and evaluate both leakage and grounding before it reaches an agent.", "A multi-tenant policy assistant retrieves internal and external knowledge.", "Poisoned chunks, cross-tenant retrieval, metadata leakage, and citation laundering turn retrieval into an attack path.", "Authorization-aware retrieval filters at the datastore, binds provenance and sensitivity, isolates instructions from evidence, and validates citations.", "cross-tenant leakage, poisoned-chunk admission, citation precision, and blocked-valid-query rate", "Can a post-generation instruction repair a secret that was already retrieved into model context?", "No. Access control and minimization must prevent unauthorized content from entering context in the first place.", "[NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)"),
    ("curriculum/intermediate/17-human-in-the-loop-security", "17 — Human-in-the-Loop Security", "Bind approval to one authenticated subject, tenant, action, resource, argument digest, expiry, and use.", "A refund agent pauses a high-risk payment for operator review.", "The model alters arguments after approval, guesses a receipt ID, replays it, or races two executions.", "A trusted approval store atomically consumes a short-lived receipt after rechecking the exact proposed action.", "approval bypass, replay success, altered-intent success, and valid-approval completion", "Is an `approved=true` field in a model proposal valid evidence?", "No. Approval must be issued and verified by trusted application state and bound to the exact action.", "[OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)"),
    ("curriculum/advanced/19-cross-agent-prompt-injection-and-message-poisoning", "19 — Cross-Agent Prompt Injection and Message Poisoning", "Preserve provenance and taint across handoffs so one compromised worker cannot turn content into authority downstream.", "A researcher sends evidence to a writer, which proposes a customer-facing action.", "A poisoned source becomes a clean-looking summary and triggers a follow-on tool call.", "Workers exchange typed artifacts with source IDs, trust labels, allowed uses, and decision receipts; consumers never treat prose as delegation.", "poison propagation, provenance loss, unsafe follow-on proposals, and valid-handoff completion", "Does a summary produced by a trusted agent become trusted instructions?", "No. Agent identity establishes attribution, not the authority or truth of the content it produced.", "[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)"),
    ("curriculum/advanced/20-cascading-failures-and-blast-radius-control", "20 — Cascading Failures and Blast-Radius Control", "Partition authority and state so a poisoned component cannot trigger unbounded downstream work or effects.", "A supervisor fans a support request into research, billing, messaging, and ticket workers.", "One malformed artifact causes retries, recursive delegation, quota exhaustion, and external writes across services.", "Per-edge contracts, fan-out and depth budgets, circuit breakers, isolated queues, idempotency, and kill switches bound the cascade.", "affected components, unauthorized effects, stop latency, retry amplification, and valid-workflow completion", "Why is a global retry policy dangerous in a multi-agent graph?", "It can amplify one failure across boundaries; retries need per-effect idempotency and bounded local policy.", "[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)"),
    ("curriculum/advanced/21-agent-to-agent-a2a-security", "21 — Agent-to-Agent (A2A) Security", "Authenticate peers and authorize every task operation independently of Agent Card discovery.", "An enterprise agent delegates a research task to an external specialist over A2A 1.0.", "A spoofed card, replayed task, cross-tenant history query, malicious artifact, or callback SSRF crosses the peer boundary.", "Verify transport and peer identity, validate cards and schemas, scope every task operation, bind idempotency, and validate callback destinations.", "spoof/replay acceptance, unauthorized task access, callback SSRF, and audit coverage", "Does an Agent Card authorize the skills it advertises?", "No. It is discovery metadata; the server must authenticate and authorize every operation.", "[A2A 1.0 specification](https://a2a-protocol.org/latest/specification/)"),
    ("curriculum/advanced/22-protocol-composition-security", "22 — Protocol Composition Security", "Carry identity, authority, provenance, correlation, and limits across UI, A2A, MCP, and downstream API hops.", "A user request crosses a web front door, supervisor, A2A specialist, MCP server, and records API.", "Each protocol is locally valid, but an audience, tenant, approval, or provenance binding disappears between hops.", "A hop ledger records authenticated actor, delegate, audience, scopes, resource, evidence, policy decision, and correlation at every translation.", "lost-identity rate, scope widening, correlation coverage, and composed attack success", "Can two individually secure protocols compose securely if identity is converted to an unverified string between them?", "No. Composition must preserve and revalidate the security invariants at every adapter.", "[MCP specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic)"),
    ("curriculum/advanced/23-agent-supply-chain-security", "23 — Agent Supply-Chain Security", "Inventory and verify the source, version, integrity, privileges, and rollback path of every agent component.", "A platform updates prompts, model packages, plugins, MCP servers, container images, and policy bundles.", "Dependency substitution, malicious updates, mutable tags, poisoned prompts, or downgraded policy enter the runtime.", "Pinned identities and digests, signed provenance, protected review, least-privilege manifests, staged rollout, and rollback guard consumption.", "verified-artifact coverage, unpinned components, provenance failures, and rollback time", "Does the presence of provenance prove an artifact is acceptable?", "No. A trusted verifier must validate it against expected source, builder, digest, and policy.", "[SLSA 1.2](https://slsa.dev/spec/v1.2/)"),
    ("curriculum/advanced/24-agent-security-testing-and-fuzzing", "24 — Agent Security Testing and Fuzzing", "Generate and minimize malformed actions, states, and protocol messages around explicit security invariants.", "A test harness exercises a typed action gateway and durable workflow state machine.", "Boundary encodings, missing fields, extreme sizes, illegal state transitions, and sequence races bypass example-based tests.", "Deterministic generators create valid and adversarial cases; an oracle checks invariants and retains minimal reproducible failures.", "invariant violations, unique failure families, minimized case size, and valid-case rejection", "What makes a fuzzer useful for security rather than merely noisy?", "A trustworthy oracle tied to explicit invariants and reproducible minimized failures.", "[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)"),
    ("curriculum/advanced/26-agent-security-observability-and-runtime-assurance", "26 — Agent Security Observability and Runtime Assurance", "Reconstruct who authorized what action from which evidence and policy without collecting secrets or private reasoning.", "A production support agent retrieves evidence, delegates, calls tools, pauses, and resumes.", "Missing correlation hides unsafe actions while over-collection leaks prompts, tokens, personal data, or confidential tool results.", "A versioned trace schema records identities, boundaries, hashes, decisions, state transitions, and effects with redaction and access policy.", "attribution and decision coverage, redaction failures, orphan effects, and detection latency", "Should observability store raw access tokens to make incidents easier to investigate?", "No. Record safe identifiers and fingerprints; telemetry itself is a sensitive data system.", "[OpenTelemetry sensitive-data guidance](https://opentelemetry.io/docs/security/handling-sensitive-data/)"),
    ("curriculum/advanced/27-threat-hunting-and-behavioral-anomaly-detection", "27 — Threat Hunting and Behavioral Anomaly Detection", "Turn observable agent trajectories into explainable hypotheses and evaluate detectors against labeled events.", "A defender analyzes tenant-scoped sequences of retrieval, delegation, tool use, denial, and egress.", "Slow scope probing, unusual fan-out, repeated approval failures, or destination drift evade single-event alerts.", "Deterministic sequence features and rules produce evidence-linked alerts that analysts can validate and tune.", "precision, recall, time to detect, alert volume, and tenant-normalized false positives", "Why is an opaque anomaly score insufficient for a security response?", "Responders need the events and rule evidence that justify containment and support tuning.", "[MITRE ATLAS](https://atlas.mitre.org/)"),
    ("curriculum/enterprise-agent/28-secure-long-running-agents", "28 — Secure Long-Running Agents", "Treat authority as a renewable lease and revalidate it whenever time, state, policy, credentials, or environment changes.", "A case-management agent pauses for hours while awaiting documents and resumes from durable state.", "Stale policy, revoked credentials, changed intent, expired approval, or outdated dependencies survive inside a checkpoint.", "Short leases, heartbeats, checkpoint integrity, policy/version binding, budget renewal, and reauthorization gate every resume.", "unsafe resume, stale-lease use, orphan-run count, and renewal denial reasons", "Does a valid checkpoint digest prove that its old authorization is still current?", "No. Integrity and present authority are separate checks; both are required on resume.", "[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)"),
    ("curriculum/enterprise-agent/31-agent-forensics-recovery-and-safe-replay", "31 — Agent Forensics, Recovery, and Safe Replay", "Build a trustworthy chronology and replay only authorized, idempotent operations from a validated checkpoint.", "An agent crashes after an external API times out with an unknown commit outcome.", "Missing events, changed policy, tampered state, or a new idempotency key duplicates a high-impact effect.", "Hash-linked receipts, protected evidence, checkpoint validation, current authorization, and provider idempotency guide replay.", "chronology completeness, tamper detection, replay correctness, and duplicate-effect count", "Why must recovery reuse the original effect identifier?", "The original idempotency identity lets the provider or application deduplicate an uncertain retry.", "[NIST SP 800-61 Rev. 2](https://csrc.nist.gov/pubs/sp/800/61/r2/final)"),
    ("curriculum/enterprise-agent/32-security-release-gates-and-production-readiness", "32 — Security Release Gates and Production Readiness", "Grant production authority only from valid, current, owned evidence with explicit severe-failure blockers.", "A change board evaluates a new support-agent release and a staged autonomy increase.", "Presence-only artifacts, stale tests, aggregate score masking, or ownerless exceptions create false assurance.", "A typed evidence dossier validates version, freshness, provenance, result, owner, rollback, and expiring risk acceptance.", "severe failures, evidence coverage and age, rollback success, and overdue exceptions", "Can a high average safety score compensate for one critical unauthorized action?", "No. Severe invariant violations remain explicit blockers outside weighted averages.", "[NIST AI RMF Playbook](https://www.nist.gov/itl/ai-risk-management-framework/nist-ai-rmf-playbook)"),
    ("curriculum/enterprise-agent/34-enterprise-agent-security-architecture", "34 — Enterprise Agent Security Architecture", "Place independent policy, isolation, evidence, and operational controls at every authority-changing enterprise boundary.", "A shared enterprise platform hosts RAG, memory, tools, MCP/A2A peers, durable workflows, and multiple tenants.", "Central credentials, implicit trust, shared state, uncontrolled egress, or missing ownership lets one compromise cross domains.", "A reference architecture maps identity, context, model, action, execution, state, protocol, telemetry, and response controls to owners.", "control and owner coverage, unmediated paths, single points of failure, and residual-risk closure", "Where should authorization live in an enterprise agent platform?", "At every protected resource and action boundary, supported by shared policy services—not inside prompts alone.", "[NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)"),
    ("curriculum/enterprise-agent/35-agent-security-architecture-review-workshop", "35 — Agent Security Architecture Review Workshop", "Find, prioritize, prove, and remediate agent-system security gaps using a repeatable evidence rubric.", "A review team receives a flawed multi-tenant support-agent design packet before launch.", "A diagram-only review misses authority flows, indirect resources, failure modes, operational owners, and untested recovery.", "Reviewers trace assets, actors, boundaries, abuse paths, invariants, controls, evidence, owners, and residual risk to concrete findings.", "finding precision, severe-gap recall, remediation quality, and reviewer agreement", "What separates an actionable finding from a generic recommendation?", "It names the violated invariant, attack path, affected asset, evidence, severity, owner, and verifiable remediation.", "[NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)"),
]


TEMPLATE = """# {title}

## Capability

{thesis}

## Learning outcomes

Learners will be able to map the relevant trust boundary, reproduce the main
attack with synthetic data, implement the independent control, inspect its
decision evidence, measure `{metric}`, and explain what remains for production.

## Enterprise scenario

{scenario}

### Primary attack

{attack}

### Governing control and invariant

{control}

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

Primary evaluation: **{metric}**. Report denominators and severe cases
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

{question}

**Expected reasoning:** {answer}

## Reference baseline

- {reference}
- [OWASP Agentic AI Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

Protocol and framework behavior is version-sensitive. The completed lesson must
pin versions in claims and label simulations, recommendations, and experimental
patterns explicitly.
"""


for relative, title, thesis, scenario, attack, control, metric, question, answer, reference in COURSES:
    path = Path(relative) / "README.md"
    path.write_text(TEMPLATE.format(**locals()))
    print(f"expanded {path}")
