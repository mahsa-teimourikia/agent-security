"""Generate the Advanced 09 notebook deterministically."""
from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "runtime_assurance.ipynb"


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
        markdown("a09-title", """
# Advanced 09 — Agent Security Observability and Runtime Assurance

**Goal:** turn minimized runtime observations into evidence-backed assurance
without trusting the model, telemetry transport, or missing spans as authority.

The default path is deterministic, credential-free, and causes no external
side effects. The final experiment uses the real OpenTelemetry Python SDK.

![Runtime assurance architecture](architecture.svg)
"""),
        markdown("a09-boundary", """
## Security boundary and success criteria

The agent, model, tool, peer, and telemetry transport may emit observations.
Trusted application code owns authenticated binding, redaction, event admission,
trace completeness, monitors, assurance state, and bounded response receipts.

Success means valid tasks remain healthy, all labeled violations are detected,
and missing collector/terminal evidence becomes `UNKNOWN` rather than safe.
"""),
        code("a09-imports", """
from dataclasses import asdict, replace
import json

import runtime_assurance as lab

cases = lab.course_cases()
print({"course": "Advanced 09", "mode": "credential-free", "cases": len(cases)})
"""),
        markdown("a09-populations", """
## 1. Start with labeled populations

Valid cases measure utility. Attack cases exercise direct violations. Boundary
cases test exact ceilings and retry behavior. Failure cases prevent outages from
being mislabeled as successful defenses.
"""),
        code("a09-case-table", """
case_rows = [{
    "id": item.case_id,
    "population": item.population.value,
    "label": item.label,
    "violation_expected": item.violation_expected,
    "consequential": item.consequential,
} for item in cases]
case_rows
"""),
        markdown("a09-valid-trace", """
## 2. Inspect a valid consequential trace

An approved refund needs application admission, an untrusted proposal, an
authoritative allow decision, atomic approval consumption before effect, a
provider-side effect observation, a budget snapshot, and terminal state.
"""),
        code("a09-valid-events", """
valid_refund = next(item for item in cases if item.case_id == "valid-refund")
binding, events = lab.events_for(valid_refund)
print(json.dumps({
    "binding": asdict(binding),
    "binding_digest": binding.digest,
    "events": [{
        "sequence": event.sequence,
        "kind": event.kind.value,
        "source": event.source,
        "authority": event.authority.value,
        "reason": event.reason_code,
        "attributes": dict(event.attributes),
    } for event in events],
}, indent=2))
"""),
        markdown("a09-assess-valid", """
The agent proposal is useful context but not authorization. The policy and
effect events are authoritative only because the application admits their
trusted sources and exact binding. The complete valid trace is `HEALTHY`.
"""),
        code("a09-valid-assessment", """
valid_assessment = lab.assess_case(valid_refund, binding, events)
print(asdict(valid_assessment))
assert valid_assessment.state is lab.AssuranceState.HEALTHY
assert valid_assessment.completeness == 1
"""),
        markdown("a09-baseline", """
## 3. Compare a naive baseline with hardened assurance

The baseline resembles log collection: it does not enforce binding and privacy
findings. The hardened monitor treats stale bindings and forbidden telemetry
attributes as security violations. Both use the same labeled cases.
"""),
        code("a09-baseline-compare", """
naive = lab.evaluate_suite(naive=True)
hardened = lab.evaluate_suite()
print(json.dumps({
    "naive": lab.report_summary(naive),
    "hardened": lab.report_summary(hardened),
}, indent=2))
assert hardened.recall > naive.recall
assert hardened.valid_false_positive_rate == 0
"""),
        markdown("a09-states", """
## 4. Keep violations distinct from missing proof

`VIOLATED` requires an admitted high/critical finding. `UNKNOWN` means the
required proof is missing, stale, foreign, or unverifiable. A collector outage
cannot become `HEALTHY` merely because no forbidden effect is visible.
"""),
        code("a09-state-matrix", """
state_matrix = [{
    "case": item.case_id,
    "population": item.population.value,
    "state": item.state.value,
    "completeness": item.completeness,
    "finding_codes": [finding.code for finding in item.findings],
} for item in hardened.assessments]
state_matrix
"""),
        markdown("a09-orphan", """
## 5. Failure injection: remove consumed approval

A consequential provider effect without a prior consumed approval is orphaned.
The agent proposal, typed attributes, or a later approval cannot repair the
ordering violation.
"""),
        code("a09-orphan-injection", """
without_approval = tuple(event for event in events if event.kind is not lab.EventKind.APPROVAL_CONSUMED)
orphaned = lab.assess_case(valid_refund, binding, without_approval)
print(asdict(orphaned))
assert orphaned.state is lab.AssuranceState.VIOLATED
assert orphaned.orphan_effects == 1
"""),
        markdown("a09-privacy", """
## 6. Failure injection: leak a sensitive attribute

Telemetry is a privileged data system. The admission allowlist blocks raw
credentials, prompts, responses, tool results, personal data, chain-of-thought,
and unclassified keys.
"""),
        code("a09-privacy-injection", """
leaky = list(events)
proposal_index = next(i for i, event in enumerate(leaky) if event.kind is lab.EventKind.AGENT_PROPOSAL)
leaky[proposal_index] = replace(leaky[proposal_index], attributes={
    **leaky[proposal_index].attributes,
    "access_token": "not-for-telemetry",
})
privacy_assessment = lab.assess_case(valid_refund, binding, leaky)
print([asdict(item) for item in privacy_assessment.findings])
assert privacy_assessment.redaction_failures == 1
assert privacy_assessment.state is lab.AssuranceState.VIOLATED
"""),
        markdown("a09-unknown", """
## 7. Failure injection: remove terminal evidence

The visible policy and effect path may look correct, but without application-
owned terminal evidence the trace contract is incomplete. The result is
`UNKNOWN`, not `HEALTHY` and not automatically `VIOLATED`.
"""),
        code("a09-unknown-injection", """
without_terminal = tuple(event for event in events if event.kind is not lab.EventKind.RUN_FINISHED)
unknown = lab.assess_case(valid_refund, binding, without_terminal)
print(asdict(unknown))
assert unknown.state is lab.AssuranceState.UNKNOWN
"""),
        markdown("a09-metrics", """
## 8. Evaluate with exact denominators

Precision and recall use labeled violation cases. Valid false-positive rate uses
only valid cases. Completeness and unknown rate use all runs. Detection latency
uses event timestamps only for findings with defined violation times.
"""),
        code("a09-metric-report", """
summary = lab.report_summary(hardened)
print(json.dumps(summary, indent=2))
assert summary["precision"] == 1
assert summary["recall"] == 1
assert summary["valid_false_positive_rate"] == 0
assert summary["unknown_rate"] == 2 / 10
"""),
        markdown("a09-response", """
## 9. Select a bounded, idempotent response

The response receipt recommends an operation; it is not authorization to carry
it out. A production executor must reauthorize the exact target/action, consume
the request once, and verify the resulting effect.
"""),
        code("a09-response-receipts", """
cross_tenant = next(item for item in hardened.assessments if item.case_id == "attack-cross-tenant")
collector_failure = next(item for item in hardened.assessments if item.case_id == "failure-collector")
receipts = [lab.response_for(cross_tenant), lab.response_for(collector_failure)]
print(json.dumps([asdict(item) for item in receipts], indent=2))
assert receipts[0].action is lab.ResponseAction.CONTAIN
assert receipts[1].action is lab.ResponseAction.ALERT
assert receipts[0] == lab.response_for(cross_tenant)
"""),
        markdown("a09-otel", """
## 10. Round-trip through the real OpenTelemetry Python SDK

The adapter uses an isolated `TracerProvider`, `SimpleSpanProcessor`, and bounded
`InMemorySpanExporter`. It emits minimized attributes and reuses the same
application monitors. Transport does not upgrade the agent proposal’s authority.
"""),
        code("a09-otel-run", """
import otel_adapter

otel_assessment = otel_adapter.run_adapter("valid-refund")
print({
    "case": otel_assessment.case_id,
    "state": otel_assessment.state.value,
    "events": len(otel_assessment.admitted_event_ids),
})
assert otel_assessment.state is otel_adapter.lab.AssuranceState.HEALTHY
"""),
        markdown("a09-production", """
## Production upgrade

| Teaching boundary | Production replacement |
| --- | --- |
| local digest | authenticated workload identity and immutable version registry |
| source-name allowlist | mTLS/SPIFFE or equivalent producer authentication |
| in-memory exporter | bounded batch OTLP pipeline and redundant collectors |
| in-process monitor | durable versioned monitor with replay/dedupe/checkpoints |
| response receipt | narrow authorization, atomic consumption, rollback, effect verification |
| fixture data | governed labeled production-like evaluation with privacy controls |

Also test sampling, cardinality, clock skew, delayed events, tenant routing,
collector outage, schema migration, monitor restart, and unknown provider effects.
"""),
        markdown("a09-exercises", """
## Exercises

1. Add a policy-deny case and prove no effect follows it.
2. Add approval expiry and replay checks.
3. Design a sampling contract that retains all required security events.
4. Add a telemetry-flood boundary case and per-tenant cardinality budget.
5. Build a separately authorized containment executor for the response receipt.
6. Explain which admitted fields A10 can safely use for behavioral detection.
"""),
        markdown("a09-summary", """
## Summary

Emit at authoritative boundaries, minimize before export, authenticate and bind
events, prove completeness, run deterministic monitors, keep missing proof
distinct from health, measure labeled populations with exact denominators, and
authorize consequential responses independently.

Continue with **Advanced 10 — Threat Hunting and Behavioral Anomaly Detection**
to build explainable hypotheses over the admitted event stream.
"""),
    ]
    return notebook


def main() -> None:
    notebook = build_notebook()
    nbf.write(notebook, OUTPUT)
    print(f"generated {OUTPUT.name} with {len(notebook['cells'])} cells")


if __name__ == "__main__":
    main()
