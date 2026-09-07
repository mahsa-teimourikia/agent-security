# Beginner 03: Secure Research Agent

Retrieval, Grounding, Citations, and Least Privilege.

## Course Metadata
- **Level**: Beginner
- **Prerequisites**: Beginner 01 (Tool Policy), Beginner 02 (Prompt Injection)
- **Time**: 60-90 minutes

## Learning Objectives
In this course, we combine the capabilities of a research assistant with the security boundaries required for enterprise deployments. You will learn:
1. Why retrieval is an authorization boundary.
2. How to distinguish between document relevance, provenance, sensitivity, and authority.
3. Why heuristic filtering of prompt injections is insufficient for security.
4. How to enforce least-privilege capability contracts.
5. How to validate model output deterministically (citations and grounding bounds).
6. Why the user-facing response must be cleanly separated from internal audit logging.
7. How to manage authoritative access contexts so callers cannot self-assert privileges.

## Why Research Agents are Security-Sensitive
Research agents combine untrusted external data (web searches, external emails) with internal sensitive data (knowledge bases, confidential documents) and feed both into a language model. 

Because the model processes all of this text simultaneously, it is impossible to guarantee the model will correctly separate data from instructions. A malicious document can instruct the model to leak the confidential data it was retrieved alongside.

## Threat Model
- **Actor**: The employee asking the question (could be an attacker via an innocent employee).
- **Poisoned Content**: Retrieved documents may contain malicious instructions designed to hijack the model (Prompt Injection).
- **Data Exfiltration**: The model might be tricked into revealing confidential documents to unauthorized users.
- **Unauthorized Actions**: The model might attempt to use tools outside its allowed scope (e.g., sending an email instead of just answering).
- **Hallucination & Laundering**: The model might fabricate citations or misrepresent retrieved evidence.
- **Privilege Escalation**: An attacker might attempt to forge their authorization context.

## Architecture

```text
User / Request
      ↓
ResearchApplication
      ↓
Identity / Entitlement Registry
      ↓
ResearchContextResolver
      ↓
SecureResearchAgent
      ↓
Retrieval
      ↓
Sensitivity Filter
      ↓
Authorized Evidence
```

## Authoritative Access Context
A key enterprise invariant is:
`typed context object != trusted actor context`

The research application resolves the user's allowed sensitivities via an authoritative registry (`IDENTITY_REGISTRY`). The normal request-facing API (`ResearchApplication.answer`) only accepts primitive strings (`subject`, `query`) and never a `ResearchContext` object.

If a public API accepted a `ResearchContext` dataclass, a malicious caller could simply construct one claiming they have `CONFIDENTIAL` access, bypassing the security model. True trust comes from the application's internal, authoritative resolution (e.g., an Identity Provider or RBAC system). The `SecureResearchAgent` itself is treated as an internal, trusted component that only receives the context *after* the application has securely resolved it.

## Retrieval is a Security Boundary
A common anti-pattern is retrieving all possible documents for a query and asking the model to "only use what the user is allowed to see." Models cannot enforce access control.

Retrieval itself must act as a hard security boundary. If the actor is not allowed to see a document (e.g., `Sensitivity.CONFIDENTIAL`), that document must be filtered out **before** it enters the model context. Data minimization before inference is critical.

*Production Caveat:* In this simulation, we perform candidate retrieval first and filter sensitivities afterward. In production, sensitive search systems often enforce authorization *inside* the retrieval index or datastore layer to avoid leaking metadata via search timing, result counts, or facets.

## Provenance vs Sensitivity vs Authority
- **Relevance**: Should this document be retrieved?
- **Provenance**: Where did this document come from? (e.g., `INTERNAL`, `EXTERNAL`).
- **Sensitivity**: Who is allowed to see this information? (e.g., `PUBLIC`, `CONFIDENTIAL`).
- **Authority**: Can this document instruct the application to perform an action? (For retrieved evidence, this should always be `INFORMATIONAL`).

*Relevant != Trusted. Trusted != Authorized. Retrieved != Safe to Execute.*

## Evidence Boundary
Retrieved content is strictly evidence. `Document.authority == INFORMATIONAL`. It can influence the answer text or the citations, but it cannot grant tool permissions or operational authority.

## User Response vs Internal Audit Evidence
The result of an LLM query must separate public response data from internal tracking data.
- **User Response**: Contains the safe answer, the safe terminal state (`ANSWERED`, `BLOCKED`, `INSUFFICIENT_EVIDENCE`), and the allowed citations. It does *not* contain the titles or IDs of blocked confidential documents.
- **Internal Audit Event**: Contains the exact candidate IDs, blocked IDs, validation reasons, and suspicious-content flags.

*Important:* Logs useful to defenders may themselves be sensitive. An unauthorized user shouldn't learn that a confidential document exists, but the audit log must record the access attempt. However, even the audit log must be redacted of actual secret values or massive user inputs.

## Grounding and Citation Validation
Citations must be deterministically validated:
1. **Citation Validity**: Does every citation exist? Was it retrieved? Was it authorized?
2. **Citation Presence**: If an answer is provided, does it cite at least one source?
3. **Grounding Evaluation**: Does that evidence actually support the claim?

*Production Caveat:* In this lab, we use `validate_grounding_fixture` to simulate deterministic detection of known, unsupported claims. In production, general grounding evaluation usually requires claim decomposition, NLI (Natural Language Inference) models, entailment checking, and human review where appropriate. It cannot always be made purely deterministic.

## Citation Laundering
"Citation Laundering" occurs when a model produces an incorrect or malicious claim, but cites a valid, trusted document to make the claim look authoritative. Presence of a citation != citation support.

## Secret / Data Minimization
Confidential data must never be retrieved for unauthorized users, and must never appear in their model context, answer, or structured audit logs.

*Note on Secrets:* While this lab uses a synthetic budget value to represent confidential data, real credentials and secrets (e.g., production API keys) should typically be managed by dedicated secrets managers and excluded from LLM context entirely, even for otherwise privileged users.

## Production Upgrades
| Teaching Simulation | Production Implementation |
|---------------------|---------------------------|
| In-memory corpus | Search / Vector / Document Platform |
| Token-overlap retrieval | BM25 / Vector / Hybrid Retrieval with row-level auth |
| `ResearchContextResolver` | IAM / Session / ABAC context provider |
| Sensitivity Enum | Classification / DLP labels |
| Static capability contract | Policy-as-code / Capability service |
| Simulated Model | LLM Endpoint |
| Deterministic citation fixtures | Claim-level grounding & Entailment checks |

## Guided Lab
Follow along in `03_secure_research_agent.ipynb` to build and test the secure research agent step-by-step.

## Exercises
(See the Jupyter Notebook for interactive exercises).
