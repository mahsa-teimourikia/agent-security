# Security Foundations and Tool Policy

| | |
|---|---|
| **Level** | Beginner |
| **Duration** | 180–240 minutes |
| **Prerequisites** | Basic Python, dictionaries, and dataclasses |
| **Notebook** | [`01_tool_policy.ipynb`](01_tool_policy.ipynb) |
| **Core lab** | [`01_tool_policy.py`](01_tool_policy.py) |
| **SDK lab** | [`01_tool_policy_sdk.py`](01_tool_policy_sdk.py) |
| **Architecture source** | [`architecture-spec.json`](architecture-spec.json) |

**Course thesis:** a model may propose a tool call, but only trusted application
policy may authorize and execute it.

## Learning Objectives

After this module you will be able to:

1. Identify assets, actors, trust boundaries, and blast radius in an agent system.
2. Distinguish trusted context (identity, tenant, scopes) from untrusted proposals (model-generated actions).
3. Implement a deterministic pre-execution policy with seven ordered controls.
4. Bind an approval to the exact arguments, run, policy version, expiry, and
   authorized approver, then consume it atomically.
5. Explain where SDK schema validation and human-in-the-loop pauses help—and
   where application authorization is still required.
6. Register a real OpenAI Agents SDK function tool with strict Pydantic input
   while keeping the exercise credential-free.
7. Produce structured, redacted audit evidence and calculate security metrics
   with explicit numerators and denominators.

## The Core Idea

Agent security protects a system that can interpret instructions, select tools,
read untrusted information, retain state, and cause side effects.  The model is
one component; **the security boundary is the application** that authenticates the
caller, authorizes each operation, validates data, limits execution, and records
evidence.  The model may propose an action, but it must not grant itself access.

## Learner Journey

1. **Break the naive design:** observe how caller-controlled identity and an
   `approved=True` flag authorize unsafe actions.
2. **Separate trust domains:** keep model proposals distinct from authenticated
   identity, resource ownership, policy, approval, and execution state.
3. **Enforce the seven controls:** run allowed, denied, paused, replay, nested
   resource, and budget-exhaustion cases.
4. **Integrate a real SDK:** inspect a generated function schema and route the
   validated payload through the same application policy gateway.
5. **Measure and reason:** inspect evidence, calculate metrics, and decide how
   the teaching implementation would change in production.

## Architecture

![Architecture diagram](architecture.svg)

The JSON [architecture specification](architecture-spec.json) is the
authoritative, reviewable geometry for the SVG. It makes the trust zones,
endpoints, and connector routes reproducible.

## A Threat-Model Vocabulary

- **Assets:** secrets, personal data, credentials, money, source code, model prompts, memory, availability, and business actions.
- **Actors:** users, agents, sub-agents, tools, MCP servers, model providers, operators, and attackers.
- **Trust boundaries:** every transition between user input, model context, tool output, memory, external systems, and human approval.
- **Blast radius:** the maximum harm if one instruction, tool, credential, or agent is compromised.

## Scenario: Expense Assistant

An expense assistant can read receipts, calculate totals, preview a claim, and submit a reimbursement.  The receipt is untrusted input, the employee identity is authenticated context, and submission is a consequential side effect.

### Control Table

| Operation | Type | Risk | Required Scope | Tenant Check | Approval | Budget Cost |
|---|---|---|---|---|---|---|
| `read_receipt` | Read-only | Low | `expense:read` | ✓ | — | 1 |
| `calculate_total` | Read-only | Low | `expense:read` | ✓ | — | 1 |
| `preview_claim` | Read-only | Low | `expense:read` | ✓ | — | 1 |
| `submit_claim` | Irreversible | **High** | `expense:submit` | ✓ | Required | 5 |

### Seven-Step Control Sequence

Before any tool executes, the policy engine checks in order:

1. **Known authenticated subject and tenant** — reject unknown principals.
2. **Operation allowlist and required scope** — reject unlisted operations or missing permissions.
3. **Resource authorization / tenant match** — resolve and authorize the primary resource and every indirectly referenced resource from trusted registry state.

> [!WARNING]
> **Nested resource bypass:** validating `proposal.resource_id` is insufficient if tool arguments contain additional document, account, file, or object IDs. Every referenced resource must receive its own authorization check.
4. **Argument schema and business rules** — reject malformed or out-of-range values.
5. **Risk classification and approval requirement** — pause high-risk writes that lack approval evidence.
6. **Approval authenticity, exact binding, expiry, and replay** — verify that the
   receipt came from the trusted approval service and an authorized approver;
   binds subject, tenant, operation, resource, canonical argument digest, run ID,
   and policy version; is within its lifetime; and is consumed exactly once.
7. **Per-run budget and stop condition** — reject when the run's cost budget is
   exhausted. Revalidate and consume the approval atomically immediately before
   returning `allow`, so concurrent attempts cannot both use it.

Only after all seven checks pass does the action reach the execution stub.

### Data Boundaries

| Structure         | Boundary                      | Authority                                          |
| ----------------- | ----------------------------- | -------------------------------------------------- |
| `ActorContext`    | Trusted application context   | Created from authenticated session / simulated IAM |
| `ActionProposal`  | Untrusted                     | Model-generated proposal                           |
| `ResourceMeta`    | Trusted lookup result         | Application resource registry                      |
| `ApprovalReceipt` | Untrusted until verified      | Issued/verified through trusted approval service   |
| `PolicyDecision`  | Trusted decision output       | Deterministic policy engine                        |
| `AuditEvent`      | Application-produced evidence | Audit pipeline                                     |

**Key Concept:** Data type ≠ trust.  A Python dataclass is not inherently trusted just because it is structured.  **Provenance and verification establish trust.**

## Tool-Call Lifecycle

```text
model proposes arguments
  → strict schema parsing
  → authenticated actor context
  → operation + resource authorization
  → business constraints
  → exact, current, one-use approval (when required)
  → budget reservation
  → effect execution
  → redacted decision + effect receipt
```

Schema validation answers “is this input well formed?” Authorization answers
“may this authenticated actor perform this exact operation on these resources,
now?” An approval answers “did an authorized reviewer consent to this exact
proposal under the current policy?” These are separate questions.

## Threat and Control Matrix

| Attack or failure | Unsafe assumption | Control and observable result |
|---|---|---|
| Prompt says “act as the CFO” | Text can establish identity | Trusted actor lookup denies `unknown_subject` |
| Proposal supplies another tenant | Model arguments define tenancy | Registry-derived ownership denies `tenant_mismatch` |
| Allowed claim contains a foreign receipt | Primary resource check covers nested IDs | Every referenced resource is checked; policy denies |
| Amount changes after approval | Approval of the action name covers all arguments | Canonical proposal digest denies `approval_proposal_mismatch` |
| Receipt is replayed or raced | Approval can be reused | Locked verify-and-consume permits at most one execution |
| Old approval survives a policy change | Approval remains valid across policy versions | Version binding denies `approval_policy_mismatch` |
| Agent loops on valid reads | Each action is harmless in isolation | Per-run cost budget denies `budget_exhausted` |
| Logs contain the full claim | Observability requires raw sensitive values | Audit stores reason, correlation, digest, and terminal state |

## State of the Art and Tool Landscape

Reviewed against official documentation in September 2026. The point is not to
pick one universal framework; it is to place each control at the boundary where
it can actually enforce a decision.

| Tool or SDK | What it contributes | What the application must still own |
|---|---|---|
| **OpenAI Agents SDK 0.22.x** | Pydantic-backed function schemas, per-tool `needs_approval`, run-state interruptions, and input/output guardrails for function tools | Identity, tenant/resource authorization, business policy, durable approval storage, and effect verification. Hosted/built-in execution tools do not all pass through the same function-tool guardrail path. |
| **LangChain / LangGraph** | Human-in-the-loop middleware can interrupt selected tools and persist an approve/edit/reject decision through a checkpointer | Reauthorize edited arguments, protect checkpoint state, and enforce policy at the final tool boundary. A workflow pause is not itself authorization. |
| **Microsoft Agent Framework** | Function-tool approval modes and middleware provide an approval interception point | Keep authorization independent of model instructions and account for differences between locally executed functions and provider-hosted tools. |
| **Pydantic v2** | Strict validation and JSON Schema generation reduce ambiguous or coercive inputs | Types do not establish identity, ownership, permission, provenance, or human consent. |
| **Open Policy Agent (OPA)** | A separate policy decision point, structured decisions, decision IDs/logs, REST and WebAssembly integration | The application remains the policy enforcement point; authenticate policy inputs, secure the OPA API, and fail closed on unavailable or invalid decisions. |
| **Cedar / Casbin** | Cedar supports analyzable authorization policies; Casbin supports established RBAC/ABAC-style enforcement models | Build policy input from trusted identity and resource state, not model-supplied claims; preserve exact action/resource semantics. |

This repository pins `openai-agents` to `>=0.22.2,<0.23` for the lab. The SDK is
pre-1.0, so a minor-version boundary is treated as an intentional review point
for public API or behavioral changes.

### Design Selection Guide

- Use **Pydantic or an SDK-generated schema** at the input boundary.
- Use **framework approval interrupts** to suspend and resume agent workflows.
- Use **application code, OPA, Cedar, or Casbin** for authoritative access and
  business decisions.
- Put the final **policy enforcement point immediately before the side effect**,
  even when an earlier agent or orchestration layer already checked the call.
- Treat provider-hosted tools as a distinct trust boundary: confirm which
  validation, guardrail, approval, and audit hooks actually execute.

## Watch For

- **Caller-asserted identity:** The model or request text must never set subject, tenant, scope, or approval.  These come from the authentication layer.  A flat `Request(subject="...", tenant="...", approved=True)` teaches the right slogan with the wrong mechanism.
- **Unverified approval Boolean:** `approved=True` as a request field lets any caller bypass approval. Production approval requires a bound, time-limited receipt verified against the subject, tenant, operation, resource, exact arguments, run, policy version, and authorized approver.
- **Check-then-use approval race:** Verification followed by a separate consume step lets two concurrent requests reuse one receipt. Verify and consume atomically at the last responsible moment.
- **Cross-tenant resource access via name:** Checking `request.tenant == "tenant-a"` does not prevent reading `tenant-b/payroll` if the resource's owning tenant is not looked up independently.
- **Budget as a soft limit:** Without enforcement, an agent can retry indefinitely.  A per-run cost budget with a stop condition limits blast radius.
- **Audit without structure:** Returning an unstructured string provides no machine-readable evidence.  Structured audit events with correlation IDs, reason codes, and terminal states enable accountability.

## Hands-On Labs

### Lab A — Build and Attack the Policy Gateway

Run the standard-library lab:

```bash
python3 curriculum/beginner/01-tool-policy/01_tool_policy.py
```

Then trace one `allow`, `deny`, and `pause` through all seven controls. Change
the approved claim amount from `250.0` to `251.0`, try the same receipt twice,
and inspect the reason code and terminal state. The invariant to preserve is:

```text
policy_state in {deny, pause} ⇒ terminal_state != executed
```

### Lab B — Integrate a Real Agents SDK Function Tool

The SDK lab registers a real function tool and inspects its generated schema,
but deliberately makes no model or network call and needs no API key:

```bash
python3 curriculum/beginner/01-tool-policy/01_tool_policy_sdk.py
```

Follow the call from `SubmitClaimInput` through `dispatch_submit_claim` to the
same `PolicyEngine`. Confirm that strict Pydantic validation rejects a numeric
string, and that `needs_approval=True` does not eliminate the application-owned
authorization check. The SDK interrupt controls orchestration; the policy
gateway controls authority.

### Lab C — Guided Notebook

Open [`01_tool_policy.ipynb`](01_tool_policy.ipynb) and work from the vulnerable
baseline through adversarial tests, SDK schema inspection, approval tampering,
and evaluation. All data is synthetic and all effects are in-memory.

## Evaluation and Evidence

The core lab reports four metrics. Each includes its population because a
percentage without a denominator can hide an unsafe or trivial test set.

| Metric | Formula | Why it matters |
|---|---|---|
| Decision accuracy | correct expected decisions / labelled decisions | Detects policy outcome regressions across allow, deny, and pause cases |
| Unauthorized execution rate | unauthorized cases that executed / unauthorized cases | Directly tests the primary safety invariant; target is zero |
| Valid-task success rate | authorized tasks executed / authorized tasks | Detects a policy that appears safe only because it blocks everything |
| Trace coverage | cases with decision and terminal evidence / evaluated cases | Ensures every result is diagnosable and auditable |

The displayed scores are deterministic results for this small teaching fixture,
not claims about a model, framework, or production system. Extend the labelled
set with organization-specific operations, resources, concurrency cases,
dependency failures, and stale policy/identity state before making deployment
decisions.

## Failure and Recovery Behavior

- **Identity, resource, approval, or policy dependency unavailable:** fail
  closed for consequential actions and emit a non-sensitive reason code.
- **Workflow resumes after a pause:** reload durable state, reauthenticate the
  actor, and reauthorize the exact proposal against current policy and resource
  state.
- **Arguments are edited during review:** create a new proposal digest and
  require authorization and approval again.
- **Executor times out:** use an idempotency key and reconcile the external
  effect before retrying; “no response” does not prove “no effect.”
- **Policy version changes:** reject stale approval and request a new decision.

## Practice and Extension Exercises

1. Add `cancel_claim` with a canonical claim resource, explicit scope, business
   transition rule, high risk, and exact approval binding. Add positive and
   adversarial tests; do not broaden the existing `submit_claim` contract.
2. Add a low-risk read tool and make it visible only to actors who can use it.
   Still enforce authorization at invocation time because discovery can become
   stale and is not a grant.
3. Implement a policy-provider interface and a small OPA, Cedar, or Casbin
   adapter. Preserve the existing `allow`/`deny`/`pause`, reason, policy-version,
   and audit contract so the enforcement point does not depend on one engine.
4. Simulate approval edits, expiry, replay, two concurrent consumers, and a
   policy-version change. Explain which evidence distinguishes each failure.
5. Add latency and dependency-status fields to redacted telemetry. Define an
   alert using both a numerator and denominator, such as approval failures per
   high-risk proposals—not a raw count alone.

## Checkpoint

1. A framework validates a `submit_claim` schema and pauses for human approval.
   What must still occur immediately before execution?
   - The application must authenticate the actor; authorize the exact operation,
     resources, and arguments under current policy; atomically consume any
     required approval; reserve budget; and record the outcome.
2. Why is a Pydantic-valid payload not necessarily authorized?
   - It proves shape and constraints, not actor identity, resource ownership,
     permission, provenance, or consent.
3. A reviewer changes an approved amount. Can the original receipt be reused?
   - No. The canonical proposal digest changes, so the policy must reauthorize
     and obtain a new approval for the edited proposal.
4. What special question should you ask about a provider-hosted tool?
   - Whether it passes through the same local validation, guardrail, approval,
     policy, and audit hooks as an application-executed function tool.
5. An employee at Acme tries to read a Globex receipt. What catches it?
   - Resource authorization derives ownership from the trusted registry and
     rejects the tenant mismatch, including for nested resource references.

## Non-Goals and Production Caveats

This lesson is a **laptop teaching simulation**, not production-grade enforcement.  The following shortcuts are intentional and clearly labelled:

| Teaching Shortcut | Production Requirement |
|---|---|
| In-memory subject registry | Real IAM / identity provider |
| In-memory resource registry | Database or catalog lookup |
| Locked in-memory, exactly bound approval receipt | Durable transaction or cryptographically signed/server-stored one-use receipt |
| In-memory budget counter | Atomic, durable budget with distributed coordination |
| Deterministic side-effect stub | Real tool call with idempotency key, effect reconciliation, and compensation where possible |
| One-process synchronization | Distributed concurrency control and durable workflow state |
| No persistent audit log | Tamper-resistant, append-only audit storage |

## References

- [OWASP Securing Agentic Applications Guide](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/) — practical technical guidance for identity, authorization, and approval in agent systems (supports Steps 1–6 of the control sequence).
- [OWASP LLM06: Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) — minimize tool functionality, permissions, and autonomy; require authorization for consequential actions.
- [Google Secure AI Framework (SAIF)](https://cloud.google.com/use-cases/secure-ai-framework) — design objectives including confidentiality, integrity, availability, and accountability (supports security objectives and audit evidence).
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) — current standards context for secure agent identity, authorization, and evaluation (ecosystem program, not a detailed implementation specification).
- [OpenAI Agents SDK: Tools](https://openai.github.io/openai-agents-python/tools/) and [Human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/) — function schemas, tool approval, and run resumption behavior.
- [OpenAI Agents SDK: Guardrails](https://openai.github.io/openai-agents-python/guardrails/) — scope and limitations of agent and tool guardrails.
- [Pydantic strict mode](https://docs.pydantic.dev/latest/concepts/strict_mode/) — preventing unintended type coercion at the data boundary.
- [LangChain human-in-the-loop middleware](https://docs.langchain.com/oss/python/langchain/human-in-the-loop) — interrupt, approve, edit, and reject workflows with checkpointing.
- [Microsoft Agent Framework tool approval](https://learn.microsoft.com/en-us/agent-framework/agents/tools/tool-approval) — function-tool approval controls and execution boundaries.
- [Open Policy Agent philosophy](https://www.openpolicyagent.org/docs/philosophy) and [REST API](https://www.openpolicyagent.org/docs/rest-api) — policy decision/enforcement separation and decision integration.
- [Cedar documentation](https://docs.cedarpolicy.com/) and [Casbin overview](https://casbin.org/docs/overview) — established authorization-policy approaches for application enforcement.

## Running the Lab

```bash
# Run the scenario evaluation
python3 curriculum/beginner/01-tool-policy/01_tool_policy.py

# Run the credential-free OpenAI Agents SDK + Pydantic integration
python3 curriculum/beginner/01-tool-policy/01_tool_policy_sdk.py

# Run the focused test suites
python3 -m pytest tests/test_tool_policy.py tests/test_tool_policy_sdk.py -v

# Run the guided notebook (from repo root)
jupyter notebook curriculum/beginner/01-tool-policy/01_tool_policy.ipynb

# Compile all curriculum Python
python3 -m compileall -q curriculum tests
```

## Learning path

Next: [Beginner 02 — Prompt Injection](../02-prompt-injection/README.md). This
integrated published lesson is also the source implementation for focused
roadmap courses [F04 — Tool Interfaces](../../roadmap/beginner/04-secure-tool-and-action-interface-design/README.md)
and [F05 — Authorization and Approval](../../roadmap/beginner/05-authorization-approval-and-least-privilege/README.md).
