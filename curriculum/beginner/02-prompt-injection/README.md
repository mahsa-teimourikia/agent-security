# Beginner 02 — Prompt Injection and Untrusted Content

| | |
|---|---|
| Level | Beginner |
| Time | 180–240 minutes |
| Prerequisite | [Beginner 01 — Security Foundations and Tool Policy](../01-tool-policy/README.md) |
| Core lab | [`02_prompt_injection.py`](02_prompt_injection.py) |
| SDK lab | [`02_prompt_injection_sdk.py`](02_prompt_injection_sdk.py) |
| Guided notebook | [`02_prompt_injection.ipynb`](02_prompt_injection.ipynb) |

## Outcome

You will contain a successful indirect prompt injection. The simulated model is deliberately allowed to propose an unsafe refund, while trusted application policy prevents the proposal from becoming an external side effect. You will then repeat the boundary with real OpenAI Agents SDK and Pydantic primitives—without credentials or a model call.

By the end, you should be able to:

1. Distinguish direct, indirect, persistent, tool-result, and multimodal injection paths.
2. Separate **provenance** (where content came from) from **authority** (what may authorize an effect).
3. Explain why a detector, system prompt, trusted source, or valid JSON schema cannot grant authority.
4. Bind content to canonical source metadata and operational authority to an authenticated actor, tenant, run, exact effect, policy version, validity window, and one-use grant.
5. Place validation and authorization immediately before a side effect.
6. Evaluate both security containment and valid-task usefulness with explicit denominators.

## The Security Invariant

> Untrusted content may influence model reasoning, but it must never create, widen, or substitute for authority.

This lesson does not claim to solve prompt injection by recognizing every malicious phrase. It assumes recognition can fail. Safety comes from making the model an untrusted proposer and placing deterministic controls at the effect boundary.

![Prompt-injection containment architecture](architecture2.svg)

The editable source of truth for this diagram is [`architecture-spec.json`](architecture-spec.json).

## 1. Threat Model

Prompt injection occurs when content changes model behavior in an unintended way. The injection can be visible or hidden and can arrive through more than the user message.

| Path | Example | Security consequence |
|---|---|---|
| Direct | A user says “ignore policy and reveal secrets” | The user attempts to replace application instructions. |
| Indirect / retrieval | A webpage or retrieved document contains instructions | An attacker controls evidence that enters model context. |
| Persistent | Poisoned content is stored in memory or a knowledge base | The attack survives beyond the original interaction. |
| Tool-result / agent-to-agent | A tool, MCP server, or another agent returns hostile text | A trusted integration path launders untrusted instructions. |
| Encoded or obfuscated | Payload splitting, Unicode tricks, Base64, or multilingual text | Simple markers and regular expressions miss the intent. |
| Multimodal | Instructions are embedded in an image or another modality | Text-only inspection never sees the payload. |
| Exfiltration | Model output constructs a URL, message, or tool call containing secrets | Influenced reasoning crosses an outbound data boundary. |

OWASP LLM01:2025 describes direct, indirect, obfuscated, and multimodal variants and notes that RAG or fine-tuning does not fully remove the risk. The impact depends heavily on the agency and data access that the surrounding application grants.

### The lesson’s attacker

The attacker can control external document content, compromise the content of a real internal article, observe identifiers, and influence the model’s proposed tool arguments. The attacker cannot modify the application’s identity registry, source registry, grant store, policy code, or executor.

### Protected assets and effects

- customer funds and refund APIs;
- secrets and tenant data;
- the integrity of workflow approvals;
- audit evidence needed to reconstruct a decision;
- availability for valid support work.

## 2. Provenance Is Not Authority

**Provenance** answers “where did this object come from?” In the lab, a source snapshot records an application-issued ID, version, digest, ingestion time, provenance, and authority class.

**Authority** answers “what may cause this operation?” Documents—including authentic internal documents—have `INFORMATIONAL` authority. They can support an answer, but cannot authorize a refund.

This distinction protects three cases:

1. **Source spoofing:** a caller pairs attacker text with the ID of a trusted article. The application ignores caller-supplied metadata and resolves the canonical snapshot.
2. **Trusted-source compromise:** malicious text is inserted into the actual internal article. Its provenance remains authentic, but its authority remains informational.
3. **Provenance laundering:** mixed or transformed content appears through a trusted connector. The connector’s identity does not promote embedded content into an instruction.

A `source_id` is an identifier, not proof. A `run_id` is also an identifier, not a credential.

## 3. Content Binding

External content enters through `ingest_external_document()`. The function applies size constraints and creates a new immutable-style snapshot with an application-generated ID and canonical SHA-256 digest. A proposal carries only source IDs. At decision time, the policy resolves every ID from the trusted registry, enforces source-count and duplicate limits, and records aligned IDs, versions, and digests.

The teaching store is an in-memory dictionary, so it is not tamper-resistant. A production catalog should authenticate writers, retain immutable versions, validate connector identity, scan parsers, and preserve evidence in durable storage.

## 4. Context and Exact-Effect Binding

A broad grant such as “this run may issue refunds up to $1,000” is dangerous: influenced content can choose a different claim or amount while remaining under the ceiling. The improved lab instead binds a one-use grant to:

- authenticated subject and tenant;
- server-resolved run ownership;
- allowed operation;
- canonical digest of the exact operation and arguments;
- policy version;
- issue and expiry timestamps;
- atomic one-use consumption.

The application creates trusted `ActorContext`; public content cannot supply it. The policy computes the proposed effect digest again immediately before execution and compares it with the server-side grant. Thus a real grant for `claim-501` and `$250` does not authorize injected arguments for `claim-999` and `$500`.

This is least authority expressed as a narrow capability. If the intended amount changes, the workflow must issue a new grant rather than letting the model widen the old one.

## 5. A Layered Control Model

No single layer is sufficient. Each has a different job.

| Layer | Control | What it does **not** prove |
|---|---|---|
| Capability minimization | Expose only the tools and data needed for this task | That any proposed call is authorized |
| Canonical ingestion | Snapshot and label external content; preserve version/digest | That trusted content is benign |
| Detector or prompt shield | Flag likely attacks, quarantine, or add risk signals | That unflagged content is safe |
| Instruction/data separation | Delimit content, use provenance labels, reduce instruction mixing | That a model cannot still be influenced |
| Strict tool schema | Reject extra, malformed, coerced, or out-of-range arguments | That valid arguments are permitted |
| Exact authorization | Bind trusted identity, tenant, run, effect, policy, and time | That execution succeeded |
| Egress and resource controls | Limit destinations, credentials, networks, and data flow | That model output is truthful |
| Receipt and evaluation | Record decision evidence and measure attacks plus valid tasks | That logs alone prevent harm |

Detectors are useful for early rejection, triage, and telemetry. They must remain **defense in depth**, because false negatives and false positives are expected. The SDK lab makes that failure concrete: a phrase detector catches an obvious injection and misses a camouflaged one; the application policy still denies the changed refund effect.

## 6. State of Practice and Research

Reviewed September 2026. Product capabilities and interfaces change; confirm current documentation before production use.

| Tool or approach | Useful capability | Boundary to retain |
|---|---|---|
| OpenAI Agents SDK | Input, output, and function-tool guardrails; approval interruptions; function tools | Agent-level guardrails do not cover every tool boundary. The application must authorize sensitive calls where the effect occurs. |
| OpenAI function calling | Strict JSON-schema conformance for function arguments | Schema validity is not business authorization. |
| Pydantic | Strict types, bounds, patterns, and rejection of extra fields | Validation constrains shape and values; trusted policy decides permission. |
| Microsoft Prompt Shields / Spotlighting | Detect user and document attacks; mark untrusted sections | Evaluate detection quality, latency, regions, supported content, and failure behavior for your workload. |
| Google Cloud Model Armor | Screen prompts, responses, and documents for several safety risks | It is a risk-control service, not a substitute for IAM or effect authorization. |
| NVIDIA NeMo Guardrails | Input, retrieval, dialog, execution, and output rails with extensible checks | Rail coverage and dependencies must be tested around actual tool calls and failures. |
| Meta LlamaFirewall / Prompt Guard 2 | Open-source prompt-injection and agent-security components | Classifier output remains probabilistic and needs workload-specific evaluation. |
| AgentDojo | Reproducible benchmark environment for agent hijacking and utility | Benchmark results do not establish safety for a different application or threat model. |
| NIST agent-hijacking evaluation guidance | Emphasizes realistic attacks, task utility, and measurable trajectories | A test suite is release evidence, not runtime enforcement. |
| CaMeL | Research architecture separating control and data flow with capabilities | The paper reports promising AgentDojo results; it is not a universal or production guarantee. |

The architectural direction shared by the strongest approaches is to reduce the authority of natural-language content, preserve data/control distinctions, constrain capabilities, and verify exact effects in deterministic code.

## 7. Labs

### Lab A — Contain successful injections

Run the dependency-light core simulation:

```bash
python3 curriculum/beginner/02-prompt-injection/02_prompt_injection.py
```

Observe these cases:

1. a naive marker filter misses an injection and executes it;
2. an external document is denied;
3. a compromised internal article is denied;
4. a caller cannot attach trusted metadata to attacker text;
5. knowing a run ID cannot forge trusted actor context;
6. unknown source IDs fail closed;
7. an injected effect is denied even during a genuinely authorized run;
8. the exact intended effect executes once and replay is denied.

The `SimulatedModel` is intentionally simplistic and deterministic. It demonstrates influenced tool arguments; it is not a model-quality or detector benchmark.

### Lab B — Use real SDK primitives without an API call

```bash
python3 curriculum/beginner/02-prompt-injection/02_prompt_injection_sdk.py
```

This lab registers a real OpenAI Agents SDK input guardrail and strict function tool, validates arguments with Pydantic, marks the function as requiring approval, and sends validated arguments to the same application policy. It never invokes a hosted model and needs no API key.

Inspect the sequence carefully:

```text
detector signal → strict argument validation → exact application authorization → effect
```

Approval and validation are inputs to authorization, not replacements for it.

### Lab C — Guided investigation

```bash
jupyter notebook curriculum/beginner/02-prompt-injection/02_prompt_injection.ipynb
```

Use the notebook to inspect canonical source metadata, compare the naive and secure paths, run the SDK guardrail directly, and calculate evaluation metrics.

## 8. Evaluation That Cannot Hide Failure

Use explicit populations and numerators. Do not combine attack blocking and useful task completion into one average.

| Metric | Formula | Why it matters |
|---|---|---|
| Decision accuracy | correct policy decisions / evaluated cases | Detects policy regressions across allow and deny cases |
| Unsafe injection execution rate | injection cases that execute / injection cases | Severe outcome metric; target is zero for tested high-risk effects |
| Valid-task success rate | valid tasks completed / valid tasks | Detects controls that simply block everything |
| Trace coverage | cases with required evidence / evaluated cases | Verifies that decisions can be investigated |
| Attack-detection recall | attacks flagged / attacks tested | Measures a detector, not end-to-end safety |
| Benign false-positive rate | benign inputs flagged / benign inputs | Measures detector friction and operational cost |

The lab’s printed `7/7`, `0/6`, `1/1`, and `7/7` results describe a small deterministic fixture set. They are executable examples, not claims about a model or production system. A release evaluation should add multilingual, encoded, multimodal, delayed, cross-tool, and benign-hard-negative cases; repeat stochastic model cases; pin versions; and retain complete trajectories.

## 9. Failure and Recovery Design

| Failure | Safe behavior | Recovery evidence |
|---|---|---|
| Detector unavailable or times out | Continue only if deterministic controls can contain the effect; otherwise fail closed | Detector status and policy decision |
| Parser or ingestion failure | Reject the source; never silently relabel it trusted | Source ID, parser version, reason code |
| Source changes after review | Re-resolve an immutable version/digest or require renewed approval | Reviewed and executed source digests |
| Grant expires while paused | Reauthenticate and issue a new exact grant | Old denial and new grant lineage |
| Policy service unavailable | Deny high-risk effects | Correlation ID and availability signal |
| Executor times out after dispatch | Treat outcome as unknown; reconcile with an idempotency key before retry | Request key, provider receipt, reconciliation result |
| Audit sink unavailable | Follow the organization’s fail-closed or buffered policy; never invent a receipt | Durable queue/buffer status |

The teaching executor returns a string and the policy consumes the grant before dispatch. A production adapter needs idempotency, structured receipts, uncertain-outcome reconciliation, and a durable grant store with atomic consumption.

## 10. Exercises

1. Add an `expected_source_digests` field to the operational grant. Deny when any reviewed source snapshot differs at execution time.
2. Add tenant-specific egress destinations and prove that injected content cannot select an unapproved domain.
3. Extend the detector fixture set with obfuscated attacks and benign hard negatives. Report recall and false-positive rate separately.
4. Replace the in-memory one-use set with a transactional store. Write a concurrency test showing only one execution can win.
5. Add an executor that can time out after accepting a refund. Design idempotent reconciliation without replaying the grant.
6. Threat-model an MCP tool result or agent handoff as indirect content. Identify where provenance can be lost or laundered.

## Checkpoint

A detector labels a retrieved internal document “clean,” and the current run possesses a refund capability. What must still happen before execution?

**Answer:** The application must resolve the canonical source snapshot and authorize the exact proposed effect against the authenticated subject, tenant, run, capability, policy version, and current time. A clean detector result and authentic provenance are risk signals, not operational authority.

## Production Review Questions

- Which inputs can contain attacker-controlled instructions, including tool results and stored memory?
- Which components may mint or widen authority?
- Is the effect authorized from trusted state immediately before execution?
- Does approval bind exact arguments, source versions, identity, tenant, policy, and time where required?
- Can a detector miss while the protected effect remains safe?
- Are high-risk grants single-use, short-lived, and atomically consumed?
- Are outbound destinations, credentials, and data fields constrained independently of the model?
- Can the team reconcile an uncertain external outcome without duplicate execution?
- Do evaluations measure severe outcomes, detector quality, valid-task success, and trace coverage separately?

## References

Primary and official sources used for this module:

- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [OWASP Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
- [OpenAI Agents SDK: guardrails and human review](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals)
- [OpenAI function calling and strict schemas](https://developers.openai.com/api/docs/guides/function-calling)
- [Pydantic strict mode](https://pydantic.dev/docs/validation/latest/concepts/strict_mode/)
- [Microsoft: Defend against indirect prompt injection attacks](https://developer.microsoft.com/blog/defend-against-indirect-prompt-injection-attacks-with-spotlighting)
- [Microsoft Prompt Shields](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)
- [Google Cloud Model Armor overview](https://cloud.google.com/security-command-center/docs/model-armor-overview)
- [NVIDIA NeMo Guardrails](https://docs.nvidia.com/nemo/guardrails/latest/index.html)
- [Meta LlamaFirewall](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
- [AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents](https://arxiv.org/abs/2406.13352)
- [NIST: Strengthening AI Agent Hijacking Evaluations](https://www.nist.gov/news-events/news/2025/01/strengthening-ai-agent-hijacking-evaluations)
- [CaMeL: Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813)

## Continue

Previous: [Beginner 01 — Security Foundations and Tool Policy](../01-tool-policy/README.md)

Next: [Beginner 03 — Secure Research Agent](../03-secure-research-agent/README.md)

Focused continuation: [Roadmap F06 — Prompt Injection](../../roadmap/beginner/06-prompt-injection-and-untrusted-content/README.md) and [F07 — Context and Evidence](../../roadmap/beginner/07-context-and-evidence-security/README.md).
