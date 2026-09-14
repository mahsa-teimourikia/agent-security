# Course review and improvement plan

Reviewed: 2026-09-12  
Governing standard: Enterprise AI Course Lifecycle  
Scope: all nine published lessons and all thirty-six canonical roadmap courses

## Executive finding

The curriculum has a strong security thesis and four unusually good published
lessons, but its current publication check proves file presence rather than
learning quality. Five published lessons still contain literal `\n`
placeholders, one-cell notebooks, or labs too small to support the stated
outcomes. The thirty-six-course expansion is correctly labelled as a roadmap,
but seventeen entries are only six-to-eight-line outlines and twenty-seven do
not yet have their own executable notebook.

The repository therefore remains a useful nine-lesson learning path, but it is
not yet a thirty-six-course program. This plan keeps that distinction explicit.
No roadmap page is promoted merely because its files exist.

## Review method and release gate

Each course was checked as one system: README, notebook, lab, tests,
checkpoint, navigation, and CI. A course is publishable only when it has:

1. one precise capability statement and three to five measurable outcomes;
2. a trust boundary, attack path, enforceable control, observable receipt, and
   residual-risk discussion;
3. a credential-free notebook that runs top to bottom and imports its own lab;
4. negative and bypass tests, not just a happy-path assertion;
5. a focused checkpoint whose explanation teaches the governing invariant;
6. working local links and successful clean CI execution.

Priority meanings:

- **P0** — published material overclaims its evidence; fix before adding lessons.
- **P1** — a useful pilot is missing one or more release-gate artifacts.
- **P2** — a planned outline needs a complete vertical slice.
- **P3** — mature material needs smaller consistency or navigation fixes.

## Published course review

| Course | Evidence reviewed | Finding | Planned improvement | Priority |
| --- | --- | --- | --- | --- |
| Beginner 01 — Tool policy | 136-line README, 978-line lab, 23-cell notebook, focused tests | Strong boundary-first course; publication evidence is real. | Add explicit prerequisite/next links and retain as the source implementation for roadmap 04–05. | P3 |
| Beginner 02 — Prompt injection | 103-line README, 407-line lab, 29-cell notebook, focused tests | Strong layered-containment lesson. `COURSE_MAP.md` incorrectly says the notebook is absent. | Fix the map and add explicit relationship to roadmap 06–07. | P3 |
| Beginner 03 — Secure research agent | 117-line README, 668-line lab, 35-cell notebook, focused tests | Strong integrated beginner capstone with evidence provenance. | Add progression links and map reusable parts to roadmap 07 and 15. | P3 |
| Intermediate 01 — Identity propagation | 201-line README, 1,107-line lab, 50-cell notebook, broad tests | Strongest course in the repository; demonstrates authenticated contexts, attenuation, audit, and attacks. | Add progression links and use it as the reference implementation for roadmap 10. | P3 |
| Intermediate 02 — MCP gateway | README contains literal placeholder escapes; 13-line lab; one-cell notebook | Published claim is not supported by the learning artifacts. | Replace with a course-specific gateway, typed call schema, audience-bound authorization, no token passthrough, quotas, receipts, attack matrix, executable notebook, and negative tests. | P0 |
| Intermediate 03 — Incident recovery | README contains literal placeholder escapes; 33-line lab; one-cell notebook | The concept is valid, but containment, investigation, recovery authorization, and replay evidence are collapsed into one toy object. | Add incident state transitions, revocation, checkpoint integrity, explicit recovery approval, idempotent effects, audit receipts, executable notebook, and negative tests. | P0 |
| Advanced 01 — Attack evaluation | README contains literal placeholder escapes; 10-line lab; two notebooks with only one code cell total | The gate uses a boolean result and cannot express severity, denominators, false blocking, coverage, or suite versions. | Build typed cases/results, severe-failure blockers, ASR and utility metrics, coverage checks, versioned evidence, executable notebook, and edge-case tests. | P0 |
| Advanced 02 — Multi-agent security | README contains literal placeholder escapes; 12-line lab; markdown-only notebook | Role lookup alone does not prove identity, scope attenuation, budgets, expiry, output provenance, or termination. | Add signed-envelope simulation, subset checks, expiry and tenant checks, budget consumption, typed artifacts, kill conditions, executable notebook, and negative tests. | P0 |
| Advanced 03 — Production gate | README contains literal placeholder escapes; 18-line lab; markdown-only notebook | Presence-only evidence can be empty or stale and the unused weights imply a risk score that is never enforced. | Add typed evidence with version/freshness/owner, severe blockers, rollback evidence, residual-risk acceptance, decision receipt, executable notebook, and negative tests. | P0 |

## Canonical roadmap review — foundation

| # | Course thesis | Current evidence | Improvement slice required before publication | Priority |
| --- | --- | --- | --- | --- |
| 01 | Secure architecture begins by making every authority-changing boundary explicit and observable. | Detailed reading page; shared pilot only. | Add boundary inventory lab, missing-boundary attack, receipt coverage metric, notebook, tests, and checkpoint. | P1 |
| 02 | A useful threat model connects assets and trust boundaries to testable abuse paths and owners. | Detailed reading page; shared pilot only. | Add structured threat records, attack-tree traversal, completeness scoring, notebook, tests, and checkpoint. | P1 |
| 03 | Security invariants turn vague intentions into properties that cap blast radius and can fail CI. | Detailed reading page; shared pilot only. | Add invariant evaluator, over-broad authority case, blast-radius metric, notebook, tests, and checkpoint. | P1 |
| 04 | Narrow typed tools reduce authority and make policy enforcement testable. | Detailed reading page; mature published source exists. | Extract a focused typed-tool slice from Beginner 01, add schema-bypass cases, notebook, tests, and checkpoint. | P1 |
| 05 | The application—not the model—must bind identity, intent, resource, expiry, and single use into approval. | Detailed reading page; mature published sources exist. | Extract deterministic PDP and atomic approval receipt exercise, notebook, replay/race tests, and checkpoint. | P1 |
| 06 | Untrusted content may contribute evidence but can never grant authority or rewrite policy. | Detailed reading page; mature published source exists. | Extract an attack matrix and layered containment lab from Beginner 02, add encoded/indirect bypasses, notebook, tests, and checkpoint. | P1 |
| 07 | Context admission must preserve provenance, authorization, freshness, and purpose before retrieval reaches a model. | Detailed reading page; mature research-agent source exists. | Add evidence-admission policy, stale/cross-tenant/poisoned cases, citation metric, notebook, tests, and checkpoint. | P1 |

## Canonical roadmap review — state and execution

| # | Course thesis | Current evidence | Improvement slice required before publication | Priority |
| --- | --- | --- | --- | --- |
| 08 | Memory is an untrusted multi-tenant data store whose reads and writes need policy, provenance, and expiry. | Partial README, 26-line lab, six-cell notebook. | Add authorization-bound reads, sensitivity and TTL, deletion, poisoning and tenant-isolation tests, richer notebook, and checkpoint. | P1 |
| 09 | Resuming durable work requires checkpoint integrity, policy freshness, reauthorization, and idempotent effects. | Good README and eight-cell notebook using shared runtime lab. | Add course-owned adapter, tamper and stale-policy tests, explicit recovery receipt, and checkpoint. | P1 |
| 10 | Delegated identity must preserve the human/workload chain while attenuating scope at every hop. | Seven-line outline; mature published source exists. | Extract a focused identity/delegation slice, confused-deputy attack, notebook, tests, and checkpoint. | P1 |
| 11 | Agents should receive short-lived, audience-bound capabilities without exposing credentials to prompts, logs, or tools. | Partial README and 24-line lab. | Add notebook, broker/audience/expiry/redaction scenarios, negative tests, and checkpoint. | P1 |
| 12 | Code execution is safe only inside an enforceable sandbox with syscall, filesystem, network, time, and resource limits. | Eight-line outline. | Add deterministic sandbox-policy simulator, traversal/escape/resource attacks, notebook, tests, and checkpoint; state clearly that simulation is not isolation. | P2 |
| 13 | Egress policy must validate scheme, normalized host, DNS/IP result, redirects, and destination purpose at every hop. | Good README, 40-line lab, seven-cell notebook. | Add redirect revalidation, IPv4/IPv6 and DNS-rebinding fixtures, request budgets, tests, and checkpoint. | P1 |
| 14 | Tool results are untrusted data and cannot become instructions or authorize follow-on actions. | Partial README and 19-line lab. | Add typed result envelope, provenance and taint propagation, notebook, bypass tests, and checkpoint. | P1 |
| 15 | Secure agentic RAG combines authorization-aware retrieval with provenance, poisoning resistance, and leakage evaluation. | Eight-line outline; mature research-agent source exists. | Extract multi-tenant retrieval slice, poisoned chunk and citation attacks, leakage/citation metrics, notebook, tests, and checkpoint. | P1 |
| 16 | MCP discovery is metadata; every call still needs server trust, schema validation, audience-bound authorization, limits, and audit. | Good README, 42-line lab, seven-cell notebook. | Align examples to current MCP 2025-11-25 authorization guidance, add token-passthrough and scope-challenge cases, tests, and checkpoint. | P1 |
| 17 | Human approval is a scoped application control, not a generic yes/no message the model can replay or alter. | Seven-line outline. | Add bound single-use receipt store, altered-intent/expiry/race attacks, notebook, tests, and checkpoint. | P2 |

## Canonical roadmap review — distributed adversaries

| # | Course thesis | Current evidence | Improvement slice required before publication | Priority |
| --- | --- | --- | --- | --- |
| 18 | A child agent must never exceed its authenticated parent’s tenant, scope, budget, lifetime, or termination condition. | Good README and seven-cell notebook using shared runtime lab. | Add course-owned adapter, budget and expiry cases, artifact provenance, tests, and checkpoint. | P1 |
| 19 | Cross-agent messages and summaries are untrusted artifacts whose provenance and taint must survive every handoff. | Seven-line outline. | Add typed handoff envelope, message-poisoning propagation metric, notebook, tests, and checkpoint. | P2 |
| 20 | Segmentation, budgets, and circuit breakers keep one poisoned agent from cascading across a workflow. | Seven-line outline. | Add dependency graph/blast-radius lab, cascade and breaker cases, notebook, tests, and checkpoint. | P2 |
| 21 | A2A metadata advertises capabilities but does not replace peer authentication or per-operation authorization. | Seven-line outline. | Add v1.0-aligned Agent Card/task simulator, spoof/replay/SSRF cases, notebook, tests, and checkpoint. | P2 |
| 22 | Identity, authority, provenance, and correlation must survive UI-to-A2A-to-MCP protocol composition. | Six-line outline. | Add hop ledger, lost-authority and audience-confusion cases, notebook, tests, and checkpoint. | P2 |
| 23 | Agent plugins, prompts, models, tools, and MCP servers need inventory, pinned identity, provenance, verification, and rollback. | Seven-line outline. | Add signed-manifest/provenance verifier, substitution and downgrade cases, notebook, tests, and checkpoint. | P2 |
| 24 | Security fuzzing should generate malformed states and arguments around explicit invariants, then minimize reproducible failures. | Seven-line outline. | Add deterministic property corpus and shrinker, schema/state attacks, notebook, tests, and checkpoint. | P2 |
| 25 | Red-team results become release evidence only when cases, environments, denominators, severity, and utility costs are versioned. | Partial README, 18-line lab, six-cell notebook. | Expand attack families, coverage and false-block metrics, severe blockers, regression tests, and checkpoint. | P1 |
| 26 | Runtime assurance requires privacy-aware traces that reconstruct identity, evidence, policy, tools, state, and effects. | Seven-line outline. | Add trace schema and completeness checker, secret-redaction cases, notebook, tests, and checkpoint. | P2 |
| 27 | Threat hunting turns trajectories into explainable hypotheses measured for precision, recall, and time to detect. | Seven-line outline. | Add deterministic event stream and detector, drift/false-positive cases, notebook, tests, and checkpoint. | P2 |

## Canonical roadmap review — enterprise operations

| # | Course thesis | Current evidence | Improvement slice required before publication | Priority |
| --- | --- | --- | --- | --- |
| 28 | Long-running agents must continuously revalidate policy, credentials, environment, intent, and budgets rather than inheriting stale authority. | Seven-line outline. | Add lease/heartbeat/resume policy, stale credential and policy cases, notebook, tests, and checkpoint. | P2 |
| 29 | Revocation must propagate quickly and force safe degradation before another external effect occurs. | Good README and five-cell notebook using shared runtime lab. | Add course-owned adapter, stop-latency metric, partial-partition cases, tests, and checkpoint. | P1 |
| 30 | Agent incident containment coordinates pause, credential revocation, egress isolation, evidence preservation, and ownership. | Good README and seven-cell notebook using shared runtime lab. | Add course-owned incident state machine, MTTC metric, failed-containment cases, tests, and checkpoint. | P1 |
| 31 | Forensics and replay require tamper-evident chronology, checkpoint validation, reauthorization, and exactly-once effects. | Six-line outline. | Add chained receipts and replay planner, missing-event/tamper/duplicate cases, notebook, tests, and checkpoint. | P2 |
| 32 | A release gate must block severe failures and invalid evidence rather than hide them in averages. | Seven-line outline; mature source exists. | Extract typed release dossier, freshness/coverage/rollback checks, notebook, tests, and checkpoint. | P1 |
| 33 | Governance makes every agent, owner, authority, dependency, risk acceptance, review date, and kill switch discoverable. | Good README, 17-line lab, six-cell notebook. | Add lifecycle transitions, overdue review and owner-loss cases, tests, and checkpoint. | P1 |
| 34 | Enterprise architecture places independent enforcement and evidence at identity, context, model, tool, state, protocol, and operations boundaries. | Seven-line outline. | Add control-coverage model and reference architecture exercise, gap cases, notebook, tests, and checkpoint. | P2 |
| 35 | Architecture review is a repeatable evidence-based challenge process, not a diagram walkthrough. | Seven-line outline. | Add flawed design packets, severity rubric, finding-quality scoring, notebook, tests, and checkpoint. | P2 |
| 36 | The capstone proves a composed agent can resist, detect, contain, recover from, and account for realistic attacks. | Partial README and 39-line dossier checker; no notebook. | Add integrated scenario, typed dossier, attack results, rollback drill, residual-risk owners, notebook, tests, and checkpoint. | P1 |

## Ordered implementation plan

1. **Repair the publication contract.** Replace the five P0 published lessons
   and make registry tests validate substance: readable Markdown, executable
   code cells, meaningful labs, focused tests, and checkpoints.
2. **Normalize the four mature published lessons.** Fix the course map and add
   clear prerequisite, next-step, and canonical-roadmap relationships.
3. **Complete foundation 01–07.** Reuse mature code only where it genuinely
   teaches the narrower course; every course still receives its own notebook,
   lab adapter or implementation, tests, and checkpoint.
4. **Complete state and execution 08–17.** Finish P1 pilots before building the
   sandbox and approval P2 slices.
5. **Complete distributed adversaries 18–27.** Pin protocol claims to the
   current MCP and A2A specifications and label evolving behavior explicitly.
6. **Complete enterprise operations 28–36.** Make incident, recovery,
   governance, architecture review, and capstone evidence interoperate.
7. **Promote only after proof.** Update Learning Hub and quiz entries one course
   at a time after its release gate passes; keep all others visibly planned.
8. **Validate twice.** Run Python tests, every notebook, local-link checks, Hub
   and quiz tests, static build, and a final claim-to-proof self-review.

## Authoritative source baseline

Course references should prefer primary sources and pin fast-moving protocol
claims to a dated version:

- NIST AI RMF 1.0 and NIST AI 600-1 Generative AI Profile for govern/map/
  measure/manage and lifecycle risk evidence.
- OWASP Agentic AI Threats and Mitigations and the OWASP Top 10 for Agentic
  Applications 2026 for the evolving agent-specific threat taxonomy.
- Model Context Protocol specification `2025-11-25` for MCP schemas,
  audience-bound tokens, least-privilege scopes, and authorization behavior.
- A2A Protocol specification 1.0 for Agent Cards, peer authentication,
  operation-level authorization, data scoping, input validation, and audit.
- SLSA specification 1.2 for artifact/source provenance and verification.
- OpenTelemetry guidance for sensitive-data handling in telemetry.

These sources inform the curriculum; they do not by themselves prove that any
course is complete. The repository’s executable evidence remains the release
gate.

## Improvements applied in this branch

- Rebuilt published Intermediate 02, Intermediate 03, Advanced 01, Advanced
  02, and Advanced 03 as complete README/lab/notebook/test slices.
- Replaced file-existence publication checks with content, notebook progression,
  executable-check, and lab-depth assertions for every published lesson.
- Normalized the four already-mature published courses with missing progression
  links, checkpoints, and the Prompt Injection notebook map correction.
- Expanded all seventeen outline-only roadmap pages into course-specific
  capability, scenario, attack, control, lab, evaluation, operations,
  checkpoint, and reference contracts.
- Added explicit Reading, Pilot, or Planned status to all thirty-six roadmap
  pages and a course-by-course status view in the Learning Hub. None were
  promoted without complete evidence.
- Pinned current fast-moving references to MCP `2025-11-25`, A2A 1.0, and SLSA
  1.2, and added deterministic notebook cell IDs for forward compatibility.

The remaining gates in the tables above are intentional backlog, not hidden
completion claims. Subsequent pull requests should take one numbered roadmap
course through its full vertical slice before changing its status to Published.
