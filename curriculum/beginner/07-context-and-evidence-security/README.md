# 07 — Context and Evidence Security

<!-- roadmap-status -->
> **Roadmap status: Reading.** The chapter is available; course-owned lab, notebook, tests, and checkpoint are still required.

## Learning objectives

Build a context-admission policy that distinguishes trusted policy, developer
instructions, user content, retrieved evidence, tool results, memory, and
agent messages; then test malicious, stale, conflicting, and unauthorized
evidence.

## Mental model

Context is a security surface, not a neutral prompt buffer. A source may be
useful evidence but never become a policy author. Every item needs a source ID,
trust class, tenant/subject scope, authorization decision, classification, and
freshness rule. These labels make later investigation possible.

| Trust class | May influence | Must not do |
| --- | --- | --- |
| Trusted policy | deterministic policy configuration | be overwritten by content |
| User/evidence/tool/memory | answer and proposal | authorize actions |
| Agent handoff | bounded task artifact | widen delegated authority |

## Practical exercise

`build_context` in `curriculum/shared/foundation_lab.py` accepts only
authorized, same-tenant items and emits a trace. It intentionally admits the
poisoned same-tenant document: provenance admission is not content trust. Add a
second stage that renders untrusted text in a data-delimited field, then verify
that it cannot affect `authorize`. Test stale, conflicting, and unauthorized
sources separately instead of silently discarding the distinction.

## Evaluation and production upgrade

Measure unauthorized-context admission, source attribution coverage, stale
evidence rate, injection-follow rate, and citation correctness. In production,
use signed/managed policy configuration, retrieval authorization, data
classification, retention controls, and privacy-aware traces. Do not claim that
instruction hierarchy alone resolves adversarial evidence.

## References

- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [MITRE ATLAS](https://atlas.mitre.org/)
