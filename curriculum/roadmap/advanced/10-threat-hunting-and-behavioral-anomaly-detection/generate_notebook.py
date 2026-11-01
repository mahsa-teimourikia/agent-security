"""Generate the Advanced 10 notebook deterministically."""
from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "threat_hunting.ipynb"


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
        markdown("a10-title", """
# Advanced 10 — Threat Hunting and Behavioral Anomaly Detection

**Goal:** turn admitted, tenant-scoped trajectories into explainable hypotheses
without treating an alert, anomaly score, or model summary as response authority.

The notebook is deterministic, credential-free, and causes no external side
effects. The final experiment uses the real pySigma 2 library.

![Threat-hunting evidence and response boundary](architecture.svg)
"""),
        markdown("a10-boundary", """
## Security boundary and success criteria

A09 admits trustworthy, minimized evidence. This course partitions that evidence
by tenant, subject, case, and event-time window; extracts deterministic features;
and creates evidence-linked hypotheses. An analyst may disposition a hypothesis.
Only a separate trusted policy may authorize a bounded response.

Success means valid workflows remain quiet, six labeled attacks are found,
failures become `UNKNOWN`, and every hypothesis cites evidence.
"""),
        code("a10-imports", """
from dataclasses import asdict, replace
import json

import threat_hunting as lab

cases = lab.course_cases()
print({"course": "Advanced 10", "mode": "credential-free", "cases": len(cases)})
"""),
        markdown("a10-populations", """
## 1. Declare labeled populations before measuring

Valid cases measure utility. Attack cases exercise known abuse. The boundary
case sits exactly at a tenant threshold. Failure cases stop missing evidence or
an unavailable detector from masquerading as safety.
"""),
        code("a10-case-table", """
case_rows = [{
    "id": item.case_id,
    "population": item.population.value,
    "tenant": item.tenant_id,
    "family": item.family,
    "attack_expected": item.attack_expected,
    "description": item.description,
} for item in cases]
case_rows
"""),
        markdown("a10-events", """
## 2. Inspect admitted sequence evidence

The slow scope-probing case uses four runs. Tenant, subject, and case stay fixed,
while distinct restricted resources accumulate inside a 15-minute event-time
window. Run ID may vary; identity scope may not.
"""),
        code("a10-slow-events", """
slow_case = next(item for item in cases if item.case_id == "attack-slow-scope")
slow_events = lab.events_for(slow_case)
[{"event": event.event_id, "run": event.run_id, "time_ms": event.event_time_ms,
  "resource": event.attributes["resource_id"], "evidence": event.evidence_ids}
 for event in slow_events]
"""),
        markdown("a10-hypothesis", """
## 3. Create an evidence-linked hypothesis

The fourth distinct restricted resource crosses tenant A's reviewed threshold.
The result records rule ID, evidence IDs, first suspicious time, and detection
time. It does not contain a containment capability.
"""),
        code("a10-slow-hunt", """
slow_result = lab.hunt_case(slow_case, slow_events)
hypothesis = slow_result.hypotheses[0]
print(json.dumps({
    "state": slow_result.state.value,
    "features": asdict(slow_result.features),
    "hypothesis": {
        **asdict(hypothesis),
        "severity": hypothesis.severity.name,
        "disposition": hypothesis.disposition.value,
    },
}, indent=2))
assert slow_result.state is lab.HuntState.HYPOTHESIS
assert len({event.run_id for event in slow_events}) == 4
"""),
        markdown("a10-baseline", """
## 4. Compare a naive exact match with sequence-aware detection

The naive baseline matches one literal egress URL. It misses the Unicode
lookalike and every sequence pattern. The hardened engine canonicalizes hosts,
uses tenant profiles, preserves order, and correlates across runs.
"""),
        code("a10-baseline-compare", """
naive = lab.evaluate_suite(naive=True)
hardened = lab.evaluate_suite()
print(json.dumps({
    "naive": lab.report_summary(naive),
    "hardened": lab.report_summary(hardened),
}, indent=2))
assert naive.recall < hardened.recall == 1
assert hardened.macro_tenant_false_positive_rate == 0
"""),
        markdown("a10-idna", """
## 5. Bypass attempt: Unicode-lookalike destination

Visual similarity is not host equality. Parse an absolute URL, reject user-info,
apply IDNA, remove a trailing dot, lowercase, and compare the canonical host to
the tenant allowlist. Detection remains defense in depth; the egress boundary
must enforce destinations independently.
"""),
        code("a10-idna-run", """
encoded_case = next(item for item in cases if item.case_id == "attack-encoded-egress")
encoded_events = lab.events_for(encoded_case)
encoded_url = encoded_events[0].attributes["destination"]
encoded_result = lab.hunt_case(encoded_case, encoded_events)
print({"raw": encoded_url, "canonical": lab.canonical_host(encoded_url),
       "state": encoded_result.state.value})
assert lab.canonical_host(encoded_url) == "xn--exfl-n9d.example"
assert encoded_result.alerted
"""),
        markdown("a10-window", """
## 6. Boundary experiment: one millisecond outside the window

Moving the first scope event just beyond the tenant's 15-minute trailing window
leaves three resources—the exact allowed threshold. Stale events must not
accumulate forever.
"""),
        code("a10-window-run", """
scope_case = next(item for item in cases if item.case_id == "attack-scope")
scope_events = [
    replace(item, event_time_ms=item.event_time_ms + 1_000_000)
    for item in lab.events_for(scope_case)
]
latest = max(item.event_time_ms for item in scope_events)
scope_events[0] = replace(scope_events[0], event_time_ms=latest - 900_001)
window_result = lab.hunt_case(scope_case, scope_events)
print({"state": window_result.state.value, "window_events": window_result.features.event_ids})
assert window_result.state is lab.HuntState.NO_HYPOTHESIS
assert len(window_result.features.event_ids) == 3
"""),
        markdown("a10-tenants", """
## 7. Tenant normalization protects utility

A five-peer batch is normal for tenant B and anomalous for tenant A. A single
global threshold either alerts on the valid batch or misses the smaller tenant's
fan-out attack.
"""),
        code("a10-tenant-run", """
batch_case = next(item for item in cases if item.case_id == "valid-batch")
batch_events = lab.events_for(batch_case)
tenant_b = lab.hunt_case(batch_case, batch_events)
tenant_a_case = replace(batch_case, tenant_id="tenant-a")
tenant_a_events = tuple(replace(event, tenant_id="tenant-a") for event in batch_events)
tenant_a = lab.hunt_case(tenant_a_case, tenant_a_events)
print({"tenant-b": tenant_b.state.value, "tenant-a": tenant_a.state.value})
assert tenant_b.state is lab.HuntState.NO_HYPOTHESIS
assert tenant_a.state is lab.HuntState.HYPOTHESIS
"""),
        markdown("a10-order", """
## 8. Order is security semantics

Four denied approvals followed by an effect attempt create an approval-pressure
hypothesis. If the effect occurred before the denials, the same counts must not
be described as pressure after denial.
"""),
        code("a10-order-run", """
approval_case = next(item for item in cases if item.case_id == "attack-approval")
approval_events = list(lab.events_for(approval_case))
ordered_result = lab.hunt_case(approval_case, approval_events)
approval_events[-1] = replace(approval_events[-1], event_time_ms=0)
reordered_result = lab.hunt_case(approval_case, approval_events)
print({"ordered": ordered_result.state.value, "effect-first": reordered_result.state.value})
assert ordered_result.alerted
assert reordered_result.state is lab.HuntState.NO_HYPOTHESIS
"""),
        markdown("a10-unknown", """
## 9. Missing evidence becomes UNKNOWN

No alert does not mean no attack when required evidence is missing. Remove one
evidence identifier from a valid sequence and preserve uncertainty rather than
claiming `NO_HYPOTHESIS`.
"""),
        code("a10-unknown-run", """
valid_case = next(item for item in cases if item.case_id == "valid-support")
valid_events = list(lab.events_for(valid_case))
valid_events[0] = replace(valid_events[0], evidence_ids=())
unknown = lab.hunt_case(valid_case, valid_events)
print({"state": unknown.state.value, "evidence_coverage": unknown.evidence_coverage})
assert unknown.state is lab.HuntState.UNKNOWN
assert unknown.evidence_coverage == 0.5
"""),
        markdown("a10-metrics", """
## 10. Evaluate with exact denominators

Recall uses all labeled attacks; an unknown attack remains a miss. Tenant false
positives use valid and boundary cases only. Failure cases contribute to unknown
rate, not a falsely improved false-positive metric. Latency uses event time.
"""),
        code("a10-metric-report", """
summary = lab.report_summary(hardened)
print(json.dumps(summary, indent=2))
assert summary["precision"] == summary["recall"] == 1
assert summary["alerts_per_100_cases"] == 50
assert summary["unknown_rate"] == 2 / 12
assert summary["mean_detection_latency_ms"] == 640_000 / 6
"""),
        markdown("a10-disposition", """
## 11. Record disposition without granting response authority

An accountable analyst can classify a hypothesis and cite supporting evidence.
The object still cannot execute containment. A separate trusted application must
authorize current role, exact scope, expiry, policy, and idempotency.
"""),
        code("a10-disposition-run", """
completed = lab.disposition(
    hypothesis,
    lab.Disposition.CONFIRMED,
    "analyst-7",
    ["case-note-31", *hypothesis.evidence_ids],
)
print({
    "disposition": completed.disposition.value,
    "analyst": completed.analyst_id,
    "support": completed.disposition_evidence_ids,
})
assert completed.disposition is lab.Disposition.CONFIRMED
assert not hasattr(completed, "response_authorized")
"""),
        markdown("a10-sigma", """
## 12. Parse and convert a real Sigma rule with pySigma 2

The adapter uses an explicit `SigmaPolicy` and pySigma's test backend. This proves
that the course rule parses and converts. It does not prove target-SIEM field
mapping, scheduling, correlation support, or response authority.
"""),
        code("a10-sigma-run", """
from pathlib import Path
import sigma_adapter

parsed = sigma_adapter.parse_and_convert(Path("agent_egress_drift.yml"))
print(asdict(parsed))
assert parsed.query == 'event_type="egress" and destination_trust="unknown"'
"""),
        markdown("a10-production", """
## Production upgrade

| Teaching boundary | Production replacement |
| --- | --- |
| deterministic local fixtures | governed replay, shadow traffic, incidents, and representative valid tasks |
| local profiles | versioned baseline service with poisoning, drift, cold-start, and rollback controls |
| trailing-window list | partitioned stream processor with watermarks, late-event revision, and checkpoints |
| evidence tuples | protected evidence store with tenant access, integrity, lifecycle, and audit |
| in-process rules | reviewed registry, backend validation, staged rollout, health monitoring, and tuning |
| disposition object | authenticated case workflow with separation of duties and immutable history |
| no response executor | narrow authorization, one-use execution, effect verification, recovery, and expiry |

Keep raw prompts, chain-of-thought, credentials, and full customer payloads out
of the hunting data plane unless a separately justified policy requires them.
"""),
        markdown("a10-exercises", """
## Exercises

1. Add a duplicate-resource event and prove unique breadth does not increase.
2. Add a watermark and an auditable late-event revision.
3. Version tenant profiles and reject a stale profile at evaluation time.
4. Express a supported sequence as a Sigma correlation and test a real backend.
5. Add an unsupervised candidate score, then prove it cannot authorize response.
6. Design a one-use pause operation and an independent effect verifier.
"""),
        markdown("a10-summary", """
## Summary

Hunt only over admitted evidence; partition by authenticated scope; define
event-time windows; compare against reviewed tenant baselines; preserve ordering,
evidence, and `UNKNOWN`; measure labeled populations with exact denominators;
and keep analyst disposition, response authorization, execution, and verification
as distinct accountable stages.

Continue to the enterprise track to apply these controls to long-running agents,
operations, incident workflows, and governance.
"""),
    ]
    return notebook


def main() -> None:
    notebook = build_notebook()
    nbf.write(notebook, OUTPUT)
    print(f"generated {OUTPUT.name} with {len(notebook['cells'])} cells")


if __name__ == "__main__":
    main()
