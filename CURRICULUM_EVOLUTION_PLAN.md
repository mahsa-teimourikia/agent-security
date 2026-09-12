# Curriculum evolution plan — AI Agent Security Engineering

## Audit conclusion

The repository has a sound, deliberately credential-free kernel: small Python
labs demonstrate authorization, injection containment, identity propagation,
MCP gateway decisions, recovery, release gating, and delegation. The Learning
Hub and quiz are working navigation surfaces. The problem is not quality of
intent; it is that the curriculum is compressed into nine broad lessons and
eight short documents. Several critical boundaries (context, durable state,
secrets, sandbox, egress, A2A, supply chain, hunting, and forensics) do not yet
have distinct, teachable units or measurable exercises.

The canonical path will therefore be `curriculum/<level>/<number-slug>/`.
Existing `docs/` and `labs/` remain available during migration as source
material and supporting references; they are not deleted or silently replaced.
Each completed canonical topic will own one deep README, one credential-free
notebook, and one deterministic `lab.py`. A shared fixture is introduced only
after two topics actually need it.

### Existing asset disposition

| Existing asset | Classification | Decision |
| --- | --- | --- |
| `README.md` | EXPAND | Convert to an accurate entry point, roadmap, setup, and reference appendix. |
| `docs/security-foundations.md` | EXPAND + SPLIT | Source for courses 01–03. |
| `docs/tools-identity-and-memory.md` | SPLIT | Source for courses 04, 05, 08, and 10. |
| `docs/prompt-injection-and-mcp.md` | SPLIT | Source for courses 06, 16, and 23. |
| `docs/production-and-evaluation.md` | SPLIT | Source for courses 24–27 and 32. |
| `docs/incident-response-and-recovery.md` | SPLIT | Source for courses 09, 30, and 31. |
| `docs/governance-and-production-readiness.md` | SPLIT | Source for courses 32–34. |
| `docs/secure-agent-capstone.md` | EXPAND | Source for course 36. |
| `docs/security-tools-and-technologies.md` | REFERENCE | Move conceptually to the technology/reference path; maintain as a curated landscape. |
| `labs/beginner/01_tool_policy.py` | EXPAND + MOVE | Course 04 reusable baseline. |
| `labs/beginner/02_prompt_injection.py` | EXPAND + MOVE | Course 06 baseline fixture. |
| `labs/beginner/03_secure_research_agent.py` | SPECIALIST LAB | Course 15 seed and course 36 component. |
| `labs/intermediate/01_identity_propagation.py` | EXPAND + MOVE | Course 10 baseline. |
| `labs/intermediate/02_mcp_gateway.py` | EXPAND + MOVE | Course 16 baseline. |
| `labs/intermediate/03_incident_recovery.py` | SPLIT + EXPAND | Courses 09, 29–31. |
| `labs/advanced/01_attack_evaluation.py` | EXPAND + MOVE | Course 25 regression harness seed. |
| `labs/advanced/02_multi_agent_security.py` | EXPAND + MOVE | Courses 18–20. |
| `labs/advanced/03_production_gate.py` | EXPAND + MOVE | Courses 32 and 36. |
| `labs/notebooks/*.ipynb` | EXPAND + MOVE | Replace shallow companions with per-topic notebooks as the topic is migrated. |
| `hub/`, `quiz/`, assets, scripts, Pages workflow | EXPAND | Preserve surfaces; drive them from the canonical registry and add validation. |

## Canonical course map

| Target course | Existing material | Action | Scenario | Main attack | Main control | Main evaluation |
| --- | --- | --- | --- | --- | --- | --- |
| 01 Architecture and trust boundaries | foundations | EXPAND | research/support agent | boundary confusion | gateway + telemetry | boundary coverage |
| 02 Threat modeling | foundations | EXPAND | expense agent | abuse path | STRIDE/attack tree | threat-record completeness |
| 03 Invariants and blast radius | foundations | NEW | claims agent | over-broad authority | measurable invariants | invariant violations |
| 04 Tool and action interfaces | tool policy | EXPAND | support actions | broad shell/tool | narrow typed tools | unauthorized action = 0 |
| 05 Authorization and approval | tool policy, identity | SPLIT | refunds | fabricated/stale approval | deterministic PDP + receipts | bypass = 0 |
| 06 Prompt injection | injection, capstone | EXPAND | poisoned ticket | indirect injection | layered containment | attack success rate |
| 07 Context and evidence | injection, research agent | NEW | policy research | poisoned/stale evidence | provenance policy | unsafe-context admission |
| 08 Memory security | identity/memory | SPLIT | support preferences | poisoned/cross-tenant memory | scoped writes and expiry | contamination/leakage |
| 09 Durable state | recovery | SPLIT | paused workflow | stale resume/replay | integrity + reauthorization | duplicate effects |
| 10 Identity and delegation | identity propagation | EXPAND | orchestrator/specialist | confused deputy | attenuated delegation | scope escalation |
| 11 Secrets and credentials | references | NEW | connector runtime | prompt/log leakage | short-lived scoped creds | exposure = 0 |
| 12 Sandbox and execution | references | NEW | code assistant | escape/resource exhaustion | runtime isolation | escape/resource bounds |
| 13 Egress and SSRF | tool policy | NEW | URL fetcher | metadata/redirect SSRF | proxy + IP/DNS checks | forbidden destination rate |
| 14 Tool-result poisoning | injection | NEW | CRM connector | malicious result instruction | schema/provenance isolation | follow-on unsafe proposal |
| 15 Agentic RAG security | research agent | EXPAND | enterprise knowledge base | poisoned/cross-tenant retrieval | auth-aware retrieval | leakage/citation metrics |
| 16 MCP security | MCP gateway | EXPAND | remote tool server | malicious server/token passthrough | authenticated gateway | policy/trace coverage |
| 17 Human approval security | tool policy | NEW | payment approval | altered/replayed approval | bound, single-use receipt | approval bypass = 0 |
| 18 Multi-agent delegation | delegation lab | EXPAND | supervisor-worker | privilege amplification | delegation envelope | child exceeds parent = 0 |
| 19 Cross-agent injection | injection, delegation | NEW | research handoff | contaminated summary | typed/provenanced artifacts | propagation rate |
| 20 Cascading failures | delegation, evaluation | NEW | support workflow | poisoned-state cascade | segmentation + kill switch | blast radius |
| 21 A2A security | NEW | NEW | external specialist | spoofed card/task replay | peer auth + task policy | rejected peer/replay |
| 22 Protocol composition | MCP/A2A | NEW | UI→A2A→MCP stack | authority confusion | hop-by-hop ledger | lost-identity rate |
| 23 Supply chain | technology guide | NEW | plugin update | compromised dependency | inventory/provenance | known artifact coverage |
| 24 Testing and fuzzing | existing tests | NEW | action gateway | malformed arguments | property/negative tests | safety properties |
| 25 Red teaming | attack evaluation | EXPAND | adversarial suite | multi-family attacks | versioned fixtures | ASR/severity/false blocks |
| 26 Observability and assurance | production evaluation | EXPAND | traced runtime | invisible unsafe action | privacy-aware traces | attribution coverage |
| 27 Threat hunting | production evaluation | NEW | trajectory stream | anomaly/drift | explainable detection | precision/recall/MTTD |
| 28 Long-running agents | recovery | NEW | scheduled case worker | stale policy/credential | resume verification | unsafe resume = 0 |
| 29 Kill switches and degradation | recovery | NEW | compromised agent | continued writes | revocation/read-only mode | stop latency |
| 30 Incident containment | incident response | EXPAND | exfiltration event | unexpected egress | isolate/revoke/preserve | MTTC |
| 31 Forensics and safe replay | incident recovery | EXPAND | failed workflow | duplicated replay | receipts/checkpoints | replay correctness |
| 32 Release gates | production gate | EXPAND | release review | average-score masking | severe-failure blocker | gate pass/fail evidence |
| 33 Governance | governance doc | EXPAND | agent inventory | ownerless autonomy | lifecycle inventory | review coverage |
| 34 Enterprise architecture | foundations/governance | NEW | enterprise platform | control gaps | reference architecture | control coverage |
| 35 Architecture review workshop | all | NEW | flawed designs | missing boundaries | formal review | finding quality |
| 36 Production capstone | capstone + all labs | EXPAND | enterprise research/support | composed attacks | defense-in-depth | security dossier |

## Delivery sequence and acceptance gates

1. **Foundation:** migrate 01–07 and establish common traces, attack fixtures,
   course template, and the Hub registry.
2. **State and execution:** migrate 08–17 with deterministic tests for scope,
   approval, resume, secrets, sandbox, egress, poisoning, RAG, and MCP.
3. **Distributed adversaries:** add 18–27 and a versioned adversarial suite.
4. **Operations and enterprise:** add 28–36, incident drills, governance, and
   the final dossier.

No course is considered complete merely because it has a page. Its README and
notebook must let a learner model a boundary, exercise an attack safely, inspect
observable state, implement and retest a control, attempt a bypass, measure the
residual risk, and explain detection, containment, recovery, and ownership.

## Source posture

Established engineering controls (authorization, least privilege, TLS,
idempotency, audit, sandboxing, secret handling, and incident response) are
kept separate from agent-specific implementation patterns and from emerging
protocol practice. Fast-moving protocol and evaluation claims are anchored to
official NIST, MCP, and A2A sources; experimental tooling is explicitly labeled
as such in the relevant course.
