"""Run the architecture-review workshop and its labelled evaluation."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json

import architecture_review as review
import review_fixtures as fixtures
from review_schema_adapter import parse_packet


@dataclass(frozen=True)
class Metric:
    numerator: int
    denominator: int
    value: float | None


@dataclass(frozen=True)
class Evaluation:
    finding_precision: Metric
    severe_gap_recall: Metric
    naive_severe_gap_recall: Metric
    remediation_quality: Metric
    reviewer_agreement: Metric


def metric(numerator: int, denominator: int) -> Metric:
    if numerator < 0 or denominator < 0 or numerator > denominator:
        raise ValueError("invalid-metric-counts")
    return Metric(numerator, denominator, numerator / denominator if denominator else None)


def reviewer_agreement(
    reviewer_a: set[str], reviewer_b: set[str], universe: set[str]
) -> Metric:
    if not reviewer_a <= universe or not reviewer_b <= universe:
        raise ValueError("finding-outside-review-universe")
    agreed = sum((key in reviewer_a) == (key in reviewer_b) for key in universe)
    return metric(agreed, len(universe))


def evaluate_workshop() -> Evaluation:
    packet = fixtures.flawed_packet()
    result = fixtures.service().review(packet, fixtures.NOW)
    predicted = {item.key for item in result.findings}
    labelled = set(fixtures.expected_keys())
    severe = set(fixtures.severe_expected_keys())
    outcomes = review.verify_remediations(
        fixtures.service(), packet, fixtures.remediated_packet(), result.findings, fixtures.NOW
    )

    reviewer_a = set(labelled)
    reviewer_b = set(labelled) - {"INV-CURRENT-EVIDENCE:encoded-export"}
    reviewer_b.add("INV-ACCOUNTABLE-OWNER:direct-refund")
    universe = set(fixtures.review_universe())

    return Evaluation(
        finding_precision=metric(len(predicted & labelled), len(predicted)),
        severe_gap_recall=metric(len(predicted & severe), len(severe)),
        naive_severe_gap_recall=metric(0, len(severe)),
        remediation_quality=metric(sum(item.verified for item in outcomes), len(outcomes)),
        reviewer_agreement=reviewer_agreement(reviewer_a, reviewer_b, universe),
    )


def run_lab() -> dict:
    packet = fixtures.flawed_packet()
    # Parse untrusted input with a real schema library; schema validity is not trust.
    parsed = parse_packet(asdict(packet))
    assert parsed == packet

    naive = review.diagram_only_review(packet)
    assert naive == ()

    service = fixtures.service()
    result = service.review(packet, fixtures.NOW)
    assert result.receipt.disposition is review.Disposition.BLOCK
    assert service.verify_receipt(result.receipt)
    assert {item.key for item in result.findings} == fixtures.expected_keys()

    # The encoded capability name cannot hide an effect path from graph-based rules.
    encoded = [item for item in result.findings if item.flow_id == "encoded-export"]
    assert {item.invariant_id for item in encoded} == {
        "INV-EFFECT-BOUNDARY", "INV-FAIL-CLOSED", "INV-ACCOUNTABLE-OWNER",
        "INV-CURRENT-EVIDENCE",
    }

    unknown = fixtures.service(evidence_available=False).review(packet, fixtures.NOW)
    assert unknown.receipt.disposition is review.Disposition.UNKNOWN

    fixed = fixtures.remediated_packet()
    final = service.review(fixed, fixtures.NOW)
    assert final.receipt.disposition is review.Disposition.PASS
    outcomes = review.verify_remediations(service, packet, fixed, result.findings, fixtures.NOW)
    assert outcomes and all(item.verified for item in outcomes)

    evaluation = evaluate_workshop()
    assert evaluation.finding_precision.value == 1.0
    assert evaluation.severe_gap_recall.value == 1.0
    assert evaluation.naive_severe_gap_recall.value == 0.0
    assert evaluation.remediation_quality.value == 1.0
    assert evaluation.reviewer_agreement.value == 0.8

    return {
        "naive_findings": len(naive),
        "structured_review": {
            "receipt": asdict(result.receipt),
            "findings": [asdict(item) for item in result.findings],
        },
        "dependency_outage": asdict(unknown.receipt),
        "remediation_outcomes": [asdict(item) for item in outcomes],
        "final_receipt": asdict(final.receipt),
        "evaluation": asdict(evaluation),
    }


if __name__ == "__main__":
    print(json.dumps(run_lab(), indent=2, default=lambda value: value.value))
