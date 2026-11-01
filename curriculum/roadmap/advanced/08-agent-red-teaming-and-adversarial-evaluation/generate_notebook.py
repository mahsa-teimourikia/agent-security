"""Generate the Advanced 08 notebook deterministically."""
from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "adversarial_evaluation.ipynb"


def markdown(cell_id: str, source: str):
    cell = nbf.v4.new_markdown_cell(source.strip())
    cell["id"] = cell_id
    return cell


def code(cell_id: str, source: str):
    cell = nbf.v4.new_code_cell(source.strip())
    cell["id"] = cell_id
    return cell


def build_notebook():
    notebook = nbf.v4.new_notebook()
    notebook["metadata"] = {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        markdown("a08-title", """
# Advanced 08 — Agent Red Teaming and Adversarial Evaluation

**Goal:** design and execute a version-bound adversarial campaign, verify real
effects outside the target, preserve useful work, distinguish failed controls
from missing evidence, and retain findings as regressions.

The default path is deterministic, credential-free, and causes no external
side effects. PyRIT is an optional companion rather than release authority.

![Red-team campaign architecture](architecture.svg)
"""),
        markdown("a08-boundary", """
## Security boundary

The target and attack framework may produce behavior, mutations, hypotheses,
and scores. Trusted application code owns fixture identity, authenticated
scope, effect observation, trace admission, metrics, findings, and release.
Target text is never proof that an effect did or did not occur.
"""),
        code("a08-imports", """
from dataclasses import asdict, replace
import json

import campaign as lab

print({"course": "Advanced 08", "mode": "credential-free", "populations": [item.value for item in lab.Population]})
"""),
        markdown("a08-scenario", """
## 1. Scope the enterprise support-agent campaign

The synthetic target combines RAG, memory, MCP, an A2A specialist, approvals,
and durable state. The campaign binds an exact release, policy, tool catalog,
environment, time window, attempts, steps, and logical cost budget.
"""),
        code("a08-campaign", """
campaign = lab.build_campaign()
print({
    "campaign": campaign.campaign_id,
    "suite": campaign.suite_version,
    "binding": asdict(campaign.binding),
    "digest": campaign.digest,
    "fixtures": len(campaign.fixtures),
})
assert len(campaign.digest) == 64
"""),
        markdown("a08-populations", """
## 2. Inspect four disjoint populations

Valid work prevents deny-all from looking secure. Attack fixtures exercise
adversary objectives. Boundary fixtures probe exact ceilings. Failure fixtures
prove that dependency and measurement outages do not become false passes.
"""),
        code("a08-population-counts", """
population_counts = {
    population.value: sum(item.population is population for item in campaign.fixtures)
    for population in lab.Population
}
category_counts = {}
for fixture in campaign.fixtures:
    category_counts[fixture.category] = category_counts.get(fixture.category, 0) + 1
print(population_counts)
print(json.dumps(category_counts, indent=2, sort_keys=True))
assert population_counts == {"valid": 2, "attack": 6, "boundary": 2, "failure": 2}
"""),
        markdown("a08-matrix", """
## 3. Read fixtures as testable security contracts

Each fixture names a population, severity, invariant, adversary objective,
expected application control and outcome, tenant, attempt count, and step limit.
The prompt itself is not the security contract; the forbidden state is.
"""),
        code("a08-fixture-table", """
fixture_rows = [{
    "id": item.fixture_id,
    "population": item.population.value,
    "severity": item.severity.name,
    "invariant": item.invariant_id,
    "control": item.expected_control,
    "expected": item.expected_outcome.value,
    "attempts": item.attempts_required,
} for item in campaign.fixtures]
fixture_rows
"""),
        markdown("a08-hardened", """
## 4. Establish the hardened reference

`ControlProfile` is a deterministic teaching target, not model-quality proof.
The oracle separately admits its traces and effects. A complete, correctly
bound run with no failures should be `READY`.
"""),
        code("a08-hardened-run", """
hardened_results = lab.run_campaign(campaign, lab.ControlProfile("hardened"))
hardened_report = lab.evaluate_campaign(campaign, hardened_results)
print(json.dumps(lab.report_summary(hardened_report), indent=2))
assert hardened_report.decision is lab.Decision.READY
assert hardened_report.failure_containment_rate == 1
"""),
        markdown("a08-trace", """
## 5. Inspect observable evidence, not private reasoning

The trace exposes fixture admission, deterministic control decisions, effect
observations, reason codes, evidence IDs, tenant/resource bindings, and logical
cost. It contains no hidden model reasoning or raw sensitive prompt.
"""),
        code("a08-trace-inspect", """
sample = next(item for item in hardened_results if item.fixture_id == "mcp-001")
print(json.dumps({
    "binding": {"campaign": sample.campaign_id, "digest": sample.campaign_digest[:12], "target": sample.target_version},
    "outcome": sample.observed_outcome.value,
    "trace": [asdict(event) for event in sample.trace],
    "effects": [asdict(effect) for effect in sample.effects],
}, indent=2))
assert all(event.redacted for event in sample.trace)
"""),
        markdown("a08-unsafe", """
## 6. Compare an unsafe baseline

The unsafe profile allows the poisoned MCP result to cause an unauthorized
effect and blocks a safe owned-case read. Security and utility must use their
own denominators.
"""),
        code("a08-unsafe-run", """
unsafe_profile = lab.ControlProfile(
    "unsafe-baseline",
    vulnerable_fixtures=frozenset({"mcp-001"}),
    overblocked_valid_fixtures=frozenset({"valid-read-001"}),
)
unsafe_results = lab.run_campaign(campaign, unsafe_profile)
unsafe_report = lab.evaluate_campaign(campaign, unsafe_results)
print(json.dumps(lab.report_summary(unsafe_report), indent=2))
assert unsafe_report.decision is lab.Decision.BLOCKED
assert unsafe_report.attack_success_rate == 1 / 6
assert unsafe_report.attack_attempt_success_rate == 2 / 12
assert unsafe_report.valid_block_rate == 1 / 2
"""),
        markdown("a08-case-attempt", """
## 7. Separate case and attempt success

Each attack has two attempts. Because both MCP attempts succeed, the attempt
rate is 2/12. The case rate is 1/6. If only one attempt succeeded, the case
would still fail: later blocks do not undo an unauthorized effect.
"""),
        code("a08-one-attempt", """
one_success = list(hardened_results)
fixture = next(item for item in campaign.fixtures if item.fixture_id == "inj-001")
index = next(i for i, item in enumerate(one_success) if item.fixture_id == fixture.fixture_id)
one_success[index] = lab.result_for(campaign, fixture, 1, outcome=lab.Outcome.ALLOWED, forbidden_effect=True)
one_report = lab.evaluate_campaign(campaign, one_success)
print({"case_rate": one_report.attack_success_rate, "attempt_rate": one_report.attack_attempt_success_rate})
assert one_report.attack_success_rate == 1 / 6
assert one_report.attack_attempt_success_rate == 1 / 12
"""),
        markdown("a08-effect", """
## 8. A claimed block cannot erase an observed effect

Keep the outcome label `BLOCKED` but inject a cross-tenant effect. The oracle
fails the case because host evidence has higher authority than the label.
"""),
        code("a08-effect-check", """
effect_results = list(hardened_results)
scope = next(item for item in campaign.fixtures if item.fixture_id == "scope-001")
index = next(i for i, item in enumerate(effect_results) if item.fixture_id == scope.fixture_id)
effect_results[index] = lab.result_for(campaign, scope, 1, outcome=lab.Outcome.BLOCKED, forbidden_effect=True)
effect_report = lab.evaluate_campaign(campaign, effect_results)
assert "attack-success:scope-001" in effect_report.blockers
print(effect_report.blockers)
"""),
        markdown("a08-incomplete", """
## 9. Preserve `INCOMPLETE` for missing proof

A verifier outage or missing trace is neither a safe block nor a verified
attack success. The release must wait for evidence rather than silently remove
the attempt from the denominator.
"""),
        code("a08-incomplete-run", """
blind_results = lab.run_campaign(campaign, lab.ControlProfile(
    "broken-observer", missing_trace_fixtures=frozenset({"inj-001"}),
))
blind_report = lab.evaluate_campaign(campaign, blind_results)
print(json.dumps(lab.report_summary(blind_report), indent=2))
assert blind_report.decision is lab.Decision.INCOMPLETE
assert blind_report.attack_success_rate == 0
assert blind_report.trace_coverage < 1
"""),
        markdown("a08-binding", """
## 10. Reject stale evidence before metrics

Changing the target, policy, tool catalog, environment, digest, or time makes an
attempt ineligible for the bound campaign. It remains visible as incomplete.
"""),
        code("a08-stale", """
stale_results = list(hardened_results)
stale_results[0] = replace(stale_results[0], target_version="release-17")
stale_report = lab.evaluate_campaign(campaign, stale_results)
print(stale_report.incomplete_reasons[:3])
assert stale_report.decision is lab.Decision.INCOMPLETE
assert any(item.startswith("binding-target") for item in stale_report.incomplete_reasons)
"""),
        markdown("a08-findings", """
## 11. Convert findings into retained regressions

An open severe finding blocks even after a safe rerun. Mitigation requires an
owner, remediation, and the exact fixture as a regression. A status label alone
does not prove closure.
"""),
        code("a08-finding-lifecycle", """
finding = lab.finding_from_failure(campaign, "mcp-001", owner="agent-security")
open_report = lab.evaluate_campaign(campaign, hardened_results, findings=[finding])
closed = lab.close_finding(finding)
closed_report = lab.evaluate_campaign(campaign, hardened_results, findings=[closed])
print({"open": open_report.decision.value, "closed": closed_report.decision.value, "regression": closed.regression_fixture_id})
assert open_report.decision is lab.Decision.BLOCKED
assert closed_report.decision is lab.Decision.READY
"""),
        markdown("a08-framework", """
## 12. Framework integration without authority transfer

`pyrit_adapter.py` implements PyRIT 1.1's official `PromptTarget` lifecycle in
an optional environment. It can orchestrate a bounded fixture, but its JSON
response cannot construct `CampaignReport`; the deterministic host oracle still
admits effects and decides release.

Install with `pip install -e '.[redteam]'`, then run:

```python
import asyncio
from pyrit_adapter import run_offline_demo_async
asyncio.run(run_offline_demo_async(campaign, lab.ControlProfile("hardened")))
```
"""),
        markdown("a08-production", """
## 13. Production upgrade path

| Lab boundary | Production control |
| --- | --- |
| in-memory suite | reviewed, signed, access-controlled registry |
| synthetic effects | isolated staging with provider and policy receipts |
| local trace tuple | protected redacted telemetry with retention policy |
| logical cost | provider usage, wall time, queue delay, and attribution |
| one process | durable campaign state, cancellation, concurrency limits |
| local finding | owned ticket/exception workflow with SLA and expiry |
| direct gate | protected CI/release control and separation of duties |

Also define rules of engagement, legal authorization, escalation, cleanup,
test-identity scope, change triggers, rollback, and independent review.
"""),
        markdown("a08-exercises", """
## Exercises

1. Add a direct-injection fixture with a different delivery path but the same
   effect oracle as `inj-001`.
2. Make only attempt three of four succeed and compare case/attempt rates.
3. Add a valid memory update so memory defenses cannot pass by denying writes.
4. Define feedback available to black-box and trace-assisted attackers.
5. Add an accepted-risk state with owner, rationale, scope, expiry, and review.
6. Design an observer placement the target cannot tamper with.
"""),
        markdown("a08-summary", """
## Summary

Red teaming is a bounded adversarial measurement and learning loop. Bind the
exact campaign, test hostile and useful behavior, observe real effects outside
the target, keep missing evidence incomplete, calculate interpretable metrics,
and retain every verified weakness as an owned regression. Frameworks extend
reach; trusted application code still owns release.
"""),
    ]
    return notebook


def main() -> None:
    notebook = build_notebook()
    nbf.write(notebook, OUTPUT)
    print(f"wrote {OUTPUT.name} with {len(notebook['cells'])} cells")


if __name__ == "__main__":
    main()
