"""Generate the Enterprise 08 architecture-review notebook deterministically."""
from pathlib import Path
import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "architecture_review_workshop.ipynb"


def md(cell_id: str, source: str):
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
        md("e08-title", """
# Enterprise 08 — Agent Security Architecture Review Workshop

**Goal:** transform an incomplete design packet into reproducible findings,
verify the repairs, and preserve honest review metrics.

![Architecture review evidence loop](architecture.svg)

This notebook is deterministic, credential-free, and makes no external calls.
Its local HMAC proves fixture integrity only; it is not deployment authority.
"""),
        md("e08-boundary", """
## Security boundary

Humans and models may propose threats. Trusted code parses the packet, derives
scope, evaluates invariants, admits evidence, records `PASS`, `BLOCK`, or
`UNKNOWN`, and verifies a new version. Schema validity and reviewer confidence
do not establish trust.
"""),
        code("e08-imports", """
from dataclasses import asdict
import json

import architecture_review as review
import review_fixtures as fixtures
from review_schema_adapter import parse_packet
import lab

packet = fixtures.flawed_packet()
print({"packet": packet.packet_id, "version": packet.version, "flows": len(packet.flows)})
"""),
        md("e08-parse", """
## 1. Parse the untrusted packet

Pydantic v2 rejects unknown fields and coercion. The result still needs tenant,
provenance, freshness, and invariant checks.
"""),
        code("e08-parse-run", """
parsed = parse_packet(asdict(packet))
assert parsed == packet
print({"assets": len(parsed.assets), "evidence": len(parsed.evidence)})
"""),
        md("e08-baseline", """
## 2. Run the diagram-only baseline

All endpoints exist, so a topology-only review reports no findings. It never
asks whether authority, tenant, effects, failure, evidence, or ownership are safe.
"""),
        code("e08-baseline-run", """
naive = review.diagram_only_review(packet)
print({"diagram_only_findings": naive})
assert naive == ()
"""),
        md("e08-review", """
## 3. Trace paths against deterministic invariants

The structured review evaluates every authority-changing and effect path and
binds its disposition to the exact packet digest and rule version.
"""),
        code("e08-review-run", """
service = fixtures.service()
result = service.review(packet, fixtures.NOW)
print(json.dumps([asdict(item) for item in result.findings], indent=2, default=lambda value: value.value))
assert result.receipt.disposition is review.Disposition.BLOCK
assert {item.key for item in result.findings} == fixtures.expected_keys()
"""),
        md("e08-encoded", """
## 4. Inspect an indirect encoded effect

The capability text is encoded, but the declared target and effect semantics
still expose missing effect controls, fail-open behavior, stale evidence, and
missing ownership. Keyword filtering would miss this path.
"""),
        code("e08-encoded-run", """
encoded = [item for item in result.findings if item.flow_id == "encoded-export"]
print([item.invariant_id for item in encoded])
assert len(encoded) == 4
"""),
        md("e08-receipt", """
## 5. Verify the review receipt

The receipt detects fixture tampering and binds the decision to packet version,
tenant, rules, time, and finding keys. It is evidence—not approval or authority.
"""),
        code("e08-receipt-run", """
print(asdict(result.receipt))
assert service.verify_receipt(result.receipt)
assert result.receipt.packet_digest == review.packet_digest(packet)
"""),
        md("e08-outage", """
## 6. Preserve uncertainty during evidence outage

Unavailable evidence cannot become an empty-finding pass. The explicit
`UNKNOWN` state routes the packet to reconciliation and a later re-review.
"""),
        code("e08-outage-run", """
unknown = fixtures.service(evidence_available=False).review(packet, fixtures.NOW)
print(asdict(unknown.receipt))
assert unknown.receipt.disposition is review.Disposition.UNKNOWN
"""),
        md("e08-remediation", """
## 7. Verify a versioned remediation

The repaired packet advances from version 3 to 4, corrects every path, and
attaches current producer-authenticated control tests. Ticket status alone
would not prove closure.
"""),
        code("e08-remediation-run", """
fixed = fixtures.remediated_packet()
final = service.review(fixed, fixtures.NOW)
outcomes = review.verify_remediations(service, packet, fixed, result.findings, fixtures.NOW)
print(json.dumps([asdict(item) for item in outcomes], indent=2))
assert final.receipt.disposition is review.Disposition.PASS
assert all(item.verified for item in outcomes)
"""),
        md("e08-metrics", """
## 8. Evaluate distinct populations

Precision, severe-gap recall, remediation quality, and reviewer agreement answer
different questions. Every value retains its numerator and denominator; a
zero-size population is `None`.
"""),
        code("e08-metrics-run", """
evaluation = lab.evaluate_workshop()
print(json.dumps(asdict(evaluation), indent=2))
assert evaluation.finding_precision.value == 1.0
assert evaluation.severe_gap_recall.value == 1.0
assert evaluation.naive_severe_gap_recall.value == 0.0
assert evaluation.remediation_quality.value == 1.0
assert evaluation.reviewer_agreement.value == 0.8
"""),
        md("e08-checkpoint", """
## Checkpoint

Two reviewers agree that mTLS protects a refund flow, and the diagram labels the
service “authorized.” The refund service receives a shared workload identity
and trusts tenant/capability fields supplied by the agent. Is this actionable
review evidence?

**Expected reasoning:** No. Agreement and diagram labels do not prove delegated
authority, resource ownership, exact capability, current policy, approval,
idempotency, or the resulting effect. The finding should name the violated
invariant and attack path; the refund owner must enforce those controls and
produce current negative and postcondition tests before independent re-review.
"""),
        md("e08-exercises", """
## Production upgrades and exercises

1. Add a memory-write flow with provenance, retention, deletion, and
   system-of-record precedence.
2. Add a bounded, expiring risk-exception receipt without changing the finding
   to “fixed.”
3. Export stable IDs to Threat Dragon, pytm, or Threagile and reconcile their
   proposed threats with the deterministic finding register.
4. Replace local evidence with an authenticated store and document key rotation,
   revocation, retention, concurrency, and failure behavior.
"""),
    ]
    return notebook


if __name__ == "__main__":
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")
