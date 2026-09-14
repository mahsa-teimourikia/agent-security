# 25 — Agent Red Teaming and Adversarial Evaluation

<!-- roadmap-status -->
> **Roadmap status: Pilot.** Some executable evidence exists; the remaining gate is listed in the Learning Hub and review plan.

## Learning objectives

Build a versioned attack suite, measure security and utility before release, inspect policy receipts and trajectories, and convert a verified finding into a regression test with an owner.

## Scenario and attack matrix

The enterprise support agent has RAG, memory, MCP, a specialist, and durable state. Test injection, tenant/scope/approval mutation, memory/replay poisoning, MCP/A2A artifact compromise, and resource pressure. Every fixture specifies expected decision, trace, severity, and affected invariant.

| Metric | Why it matters |
| --- | --- |
| Attack success rate | captures failed containment |
| Severe successes | blocks release regardless of averages |
| Blocked-valid-task rate | exposes harmful overblocking |
| Trace coverage | proves a failure is attributable |
| Adversarial latency/cost | detects availability degradation |

## Practical lab

Run `python curriculum/advanced/25-agent-red-teaming-and-adversarial-evaluation/lab.py`. The baseline blocks high-severity fixtures while surfacing a deliberately blocked safe read. Add a high-severity MCP poisoning success: release readiness becomes false even if the average score appears good.

## Production gate

Record fixture and environment versions, policy/model/tool versions, expected and observed outcome, redacted trace, severity, owner, and remediation. Block release on any high-severity success or missing trace. Tools such as AgentDojo, ToolEmu, garak, and PyRIT expand coverage; they do not replace application controls or a severity decision.

## References

- [MITRE ATLAS](https://atlas.mitre.org/)
- [AgentDojo](https://arxiv.org/abs/2406.13352)
- [ToolEmu](https://arxiv.org/abs/2309.15817)
