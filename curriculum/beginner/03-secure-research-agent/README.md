# Beginner 03: Secure Research Agent

Build a research pipeline in which retrieved content is evidence—not instructions, identity, authority, or permission.

![Secure research agent architecture](architecture.svg)

## Course metadata

- **Level:** Beginner
- **Prerequisites:** [Beginner 01 — Tool Policy](../01-tool-policy/README.md) and [Beginner 02 — Prompt Injection](../02-prompt-injection/README.md)
- **Time:** 3–4 hours
- **Format:** concept review, deterministic Python lab, credential-free SDK lab, adversarial tests, and evaluation
- **Last reviewed:** 2026-09-17

## Outcomes

By the end, you can:

1. Threat-model a retrieval-augmented research agent across identity, ingestion, retrieval, generation, release, and audit boundaries.
2. Enforce tenant, sensitivity, and document-lifecycle rules **before** ranking.
3. Keep caller-controlled values out of trusted identity and entitlement context.
4. Bind claims to the exact retrieved document ID, version, and content digest.
5. Reject action proposals, unknown or stale citations, citation laundering, and unsupported claims outside the model.
6. Separate safe user output from data-minimized defender telemetry.
7. Register a strict, read-only OpenAI Agents SDK tool whose arguments cannot assert authorization.
8. Evaluate safety, utility, citation integrity, abstention, and trace coverage separately.

## The security thesis

The model is a probabilistic proposer inside a deterministic control plane:

```text
authenticate → resolve entitlements → security-trim → rank → snapshot
             → model drafts claims/citations → verify → release or abstain
```

The order matters. “Retrieve everything, then ask the model not to use secrets” exposes secrets to the model. “Rank everything, then filter” can still reveal existence, counts, timing, or facets. This lab therefore removes unauthorized, cross-tenant, expired, and superseded records before tokenization or relevance scoring.

## Threat model

| Boundary | Failure | Security consequence | Lab control |
|---|---|---|---|
| Request → identity | Caller supplies a role, tenant, or sensitivity | Privilege escalation | Server-side `ResearchContextResolver` |
| Ingestion → corpus | Missing or forged classification metadata | Incorrect access decisions | Canonical metadata and trusted digest generation |
| Corpus → retriever | Global ranking precedes authorization | Cross-tenant or sensitive metadata leakage | Security trimming before ranking |
| Evidence → model | Poisoned text is interpreted as instructions | Prompt injection or action proposal | Evidence is always `INFORMATIONAL`; model has no side-effect tool |
| Model → release | Citation is missing, fabricated, stale, or irrelevant | Unsupported answer or citation laundering | Exact evidence refs plus claim-level fixture oracle |
| Request → audit | Raw queries and secrets are logged | Secondary disclosure | Query digest/length and bounded structured receipts |
| Control outage | Policy or identity lookup fails open | Unauthorized access | Unknown identity and missing evidence fail closed |

### Assets and trust assumptions

- **Protected assets:** confidential text, tenant boundaries, current policy truth, identities, entitlements, and audit integrity.
- **Untrusted inputs:** queries, retrieved text, model output, citations proposed by the model, and action proposals.
- **Trusted components:** authenticated application session, entitlement resolver, retrieval filter, canonical ingestion metadata, deterministic validators, and audit sink.
- **Out of scope:** cryptographic identity proof, production vector infrastructure, and a general-purpose semantic entailment model. The lab labels its fixture oracle honestly.

## Four dimensions that must not collapse

| Dimension | Question | Example control |
|---|---|---|
| Relevance | Does the record help answer this query? | BM25, vector, or hybrid ranking |
| Provenance | Where did it come from? | Internal repository vs. external web content |
| Sensitivity | May this actor access it? | Tenant, ACL, RBAC/ABAC, classification label |
| Authority | May it instruct the application to act? | Retrieved evidence remains informational |

Relevant is not trusted. Trusted is not authorized. Authorized evidence is still not permission to act.

## 1. Resolve identity outside the model

`ResearchApplication.answer(subject, query)` deliberately has no tenant, role, sensitivity, or context parameter. It resolves `ResearchContext` from authoritative application state. A typed object is not automatically trusted: accepting a caller-created `ResearchContext` would simply turn its fields into privilege-escalation inputs.

In production, derive this context from a verified session or workload identity, then resolve current ACL/RBAC/ABAC policy. Do not let the model choose a tenant namespace or invent filters.

## 2. Authorize before ranking

`RetrievalService.search` applies all three rules before scoring:

1. document tenant is the actor’s tenant or the explicitly shared `global` tenant;
2. document sensitivity is in the actor’s entitlement set; and
3. lifecycle is active and the validity window includes the evaluation time.

Only eligible records are tokenized and ranked. The test suite proves that Acme confidential data, Globex data, and a superseded retention policy are absent from `scored_document_ids` for Alice.

Security trimming depends on correct, current metadata. A stale ACL cache or mislabeled record can invalidate an otherwise correct query filter. Treat ingestion, entitlement freshness, index updates, deletion, and policy outages as part of the access-control system—not plumbing.

## 3. Freeze evidence snapshots

Each result becomes an immutable `EvidenceSnapshot` with:

- stable document ID;
- version;
- SHA-256 content digest;
- title and text supplied to the model;
- provenance, sensitivity, and informational authority; and
- exact supported claims for this deterministic fixture.

A citation is an `EvidenceRef(document_id, version, content_digest)`. A model cannot cite an older version using the current document ID, or cite content whose digest differs from what the verifier received.

This lab’s user-facing citation is compact (`doc-int-01@v3`); the full digest remains in the internal evidence receipt. Production systems may also bind chunk ID, page/section, index generation, retrieval time, and policy version.

## 4. Treat the model output as a proposal

The simulated model returns:

- answer text;
- atomic `ClaimDraft` objects;
- exact evidence references per claim; and
- an optional action proposal.

Trusted validators run in a fixed order:

1. **Capability:** this research model has no side-effect capability, so every action proposal is denied.
2. **Citation integrity:** every claim needs a citation, and every reference must exactly match the evidence supplied in this run.
3. **Grounding fixture:** normalized claims must occur in the synthetic supported-claim registry of at least one cited snapshot.

The grounding check is intentionally a closed-world teaching oracle. Exact matching is not general semantic entailment. Production evaluation can combine claim decomposition, natural-language inference or LLM judges, deterministic domain rules, and human review according to consequence.

## 5. Separate response from audit

`ResearchResponse` contains only a terminal state, safe answer, verified citation labels, and application-generated correlation ID. It never lists filtered record IDs.

`AuditEvent` records a query digest and length—not the raw query—plus policy/scope receipts, IDs of authorized records considered, evidence snapshot labels, model citation labels, detector signal, decision, and reason. Audit access, retention, redaction, and export controls remain necessary because telemetry is a sensitive system of record.

The three terminal states are deliberate:

- `answered`: deterministic release checks passed;
- `insufficient_evidence`: authorized/current evidence is absent or cannot support the claim; and
- `blocked`: identity, capability, or integrity policy failed.

Do not expose a detailed denial reason if it would reveal that a secret or another tenant’s record exists.

## Detection is defense in depth

`detect_suspicious_content` improves triage, but one poisoned fixture bypasses it and is still blocked. The security property comes from architecture: restricted retrieval, informational evidence, no side-effect executor, exact citations, and deterministic release checks. A detector can miss, over-block, or be evaded; it cannot grant access or authority.

## State of practice and tool review

The following capabilities are useful building blocks, not complete security guarantees. Verify current behavior for your exact version and backend.

| Tool or SDK | Relevant capability | Secure use in this architecture | Boundary/caveat |
|---|---|---|---|
| OpenAI Vector Stores | Attribute filters in search | Derive filters from trusted runtime context | Filter quality depends on authoritative attributes and update freshness |
| OpenAI Agents SDK | Typed runtime context and strict function tools | Keep identity in `RunContextWrapper`; expose only a bounded query argument | The SDK runs the tool loop; your application still owns authorization and release policy |
| Azure AI Search | Document-level access, security filters, ACL/RBAC approaches | Apply permission metadata at indexing and query time | Preview feature coverage and stale ACL behavior vary; fail closed on authorization-evaluation failure |
| Pinecone | Namespaces and metadata filters | Use a tenant namespace and additional document policy filters | Namespace selection must come from trusted identity, never model arguments |
| Weaviate | Tenant-specific shards and tenant-scoped queries | Bind the client/collection to the resolved tenant before search | Tenant deletion and lifecycle operations are security-sensitive administration |
| LlamaIndex | `MetadataFilters` and retriever/query-engine composition | Pass trusted filters into the vector query and preserve source-node metadata | Framework composition does not make caller-supplied filters trustworthy |
| RAGChecker | Claim-level diagnostic metrics for retriever and generator | Add offline faithfulness and retrieval diagnostics | Model-based metrics need validation against human judgments for the target domain |

Primary references:

- [OWASP LLM08:2025 — Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)
- [OpenAI Agents SDK guide](https://developers.openai.com/api/docs/guides/agents/sdk), [strict function calling](https://developers.openai.com/api/docs/guides/function-calling), and [vector-store search filters](https://developers.openai.com/api/reference/python/resources/vector_stores/methods/search)
- [Azure AI Search document-level access overview](https://learn.microsoft.com/en-us/azure/search/search-document-level-access-overview), [security best practices](https://learn.microsoft.com/en-us/azure/search/search-security-best-practices), and [query-time ACL enforcement](https://learn.microsoft.com/en-us/azure/search/search-query-access-control-rbac-enforcement)
- [Pinecone multitenancy](https://docs.pinecone.io/guides/index-data/implement-multitenancy) and [metadata filters](https://docs.pinecone.io/guides/search/filter-by-metadata)
- [Weaviate multi-tenancy operations](https://docs.weaviate.io/weaviate/manage-collections/multi-tenancy)
- [LlamaIndex vector-store query API](https://docs.llamaindex.ai/en/stable/api_reference/storage/vector_store/#llama_index.core.vector_stores.types.VectorStoreQuery)
- [RAGChecker, NeurIPS 2024](https://papers.nips.cc/paper_files/paper/2024/file/27245589131d17368cccdfa990cbf16e-Paper-Datasets_and_Benchmarks_Track.pdf)
- [NIST AI 600-1, Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

## Labs

### Lab A — deterministic secure pipeline

Run the reference implementation:

```bash
python curriculum/beginner/03-secure-research-agent/03_secure_research_agent.py
```

Then use [the notebook](03_secure_research_agent.ipynb) to inspect each boundary. You will compare normal retrieval, unauthorized confidential access, cross-tenant search, a superseded policy, prompt injection, detector bypass, fabricated and stale citations, citation laundering, missing evidence, and unknown identity.

Expected observations:

- Alice’s confidential Acme record is never scored.
- Bob’s Acme access never scores the similarly named Globex record.
- the superseded 365-day policy is never scored;
- authorized Bob receives the current `$4.2M` synthetic Acme answer;
- poisoned content may reach the model when it is authorized evidence, but it cannot acquire a side-effect capability; and
- an answer is released only with an exact current citation and supported claim.

### Lab B — strict OpenAI Agents SDK tool

Run the credential-free companion:

```bash
python curriculum/beginner/03-secure-research-agent/03_secure_research_agent_sdk.py
```

It constructs an `Agent[SDKRuntime]` and registers one `@function_tool(strict_mode=True)`. The generated schema has a single required `query` property with `additionalProperties: false`. `subject`, `tenant_id`, and `allowed_sensitivities` live only in the server-created runtime context. The script directly dispatches the tool’s underlying application boundary; it does not invoke a model or require an API key.

### Lab C — adversarial verification

Run the focused test suite:

```bash
pytest -q tests/test_secure_research_agent.py
```

Read each test as a security claim. If a refactor changes the order to rank-then-filter, accepts caller entitlements, logs raw queries, or weakens citation binding, the corresponding test should fail.

### Lab D — safety and utility evaluation

`evaluate_fixture()` reports:

- unsafe disclosures;
- unsafe actions executed;
- valid-answer success rate;
- expected-abstention accuracy;
- citation integrity rate; and
- trace coverage rate.

Do not collapse these into one average. A system can appear “safe” by refusing every request, or appear “helpful” by leaking data. Production gates should set separate thresholds, include tenant and policy slices, track confidence intervals, and retain human-reviewed cases for high-consequence domains.

## Failure and recovery playbook

| Signal | Immediate behavior | Investigation | Recovery evidence |
|---|---|---|---|
| Identity/entitlement lookup unavailable | Fail closed; return generic blocked state | IdP, cache, policy service, clock | Auth dependency healthy; negative-access tests pass |
| ACL or classification freshness unknown | Exclude affected corpus/tenant | Ingestion lag, tombstones, policy revision | Index generation reconciled to source of truth |
| Cross-tenant record appears in scored IDs | Stop release and isolate index | Namespace/filter derivation and routing | Full tenant-isolation regression suite passes |
| Evidence digest/version mismatch | Block output | Concurrent update, stale cache, tampering | Snapshot and canonical store reconcile |
| Citation/grounding failure spike | Abstain, preserve minimized trace | Retriever quality, model change, corpus drift | Offline labelled suite and sampled human review pass |
| Poisoned content proposes an action | Deny action and alert by risk tier | Source provenance and detector telemetry | Capability contract still has no side-effect executor |
| Audit sink unavailable | Follow documented fail-closed or buffered mode | Durability, backpressure, retention | Correlation and trace-coverage checks restored |

## Exercises

1. Add an `expires_at` document and prove it is neither scored nor exposed after expiry.
2. Add a second current chunk for the retention policy and require a claim to cite both supporting snapshots.
3. Replace token overlap with a local vector or BM25 retriever while preserving the pre-ranking authorization test.
4. Add an ACL revision to the scope receipt and reject a release if the revision changes during the request.
5. Add labelled evaluation cases for wrong-tenant abstention, citation digest mismatch, duplicated citations, and audit-sink failure.
6. Design a human-review terminal state for high-consequence claims. Specify what the reviewer sees without exposing unrelated sensitive records.

## Review checklist

- [ ] Is identity authenticated and resolved outside model/tool arguments?
- [ ] Are tenant, ACL/sensitivity, lifecycle, and freshness applied before ranking?
- [ ] Can filtered record IDs, counts, facets, or timing leak to the caller?
- [ ] Does every released claim cite the exact evidence snapshot used in the run?
- [ ] Can retrieved content grant a tool, role, tenant, or permission?
- [ ] Are high-impact actions absent or independently authorized at execution time?
- [ ] Do logs avoid raw secrets and unnecessary personal data?
- [ ] Are policy outages and stale metadata fail-closed?
- [ ] Are safety and useful-answer metrics gated separately?
- [ ] Can an operator reconstruct the decision from minimized policy and evidence receipts?

## Checkpoint

**Why is filtering after vector ranking insufficient?**

Because unauthorized records have already participated in computation. Their existence can affect timing, counts, facets, and ranking behavior, and a control bug can pass them downstream. Security-trim with trusted identity and current policy first; rank only the eligible corpus.

Previous: [Beginner 02 — Prompt Injection](../02-prompt-injection/README.md)

Next: [Intermediate 01 — Identity Propagation](../../intermediate/01-identity-propagation/README.md)

Focused continuation: [F07 — Context and Evidence Security](../../roadmap/beginner/07-context-and-evidence-security/README.md) and [I08 — Agentic RAG Security](../../roadmap/intermediate/08-agentic-rag-security/README.md).
