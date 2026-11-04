"""Invariant tests for Enterprise Course 08 architecture review workshop."""
from dataclasses import asdict, replace
import importlib.util
from pathlib import Path
import sys

import pytest
from pydantic import ValidationError


ROOT = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/08-agent-security-architecture-review-workshop"
sys.path.insert(0, str(ROOT))
import architecture_review as review  # noqa: E402
import review_fixtures as fixtures  # noqa: E402
from review_schema_adapter import parse_packet  # noqa: E402

LAB_SPEC = importlib.util.spec_from_file_location("enterprise_08_course_lab", ROOT / "lab.py")
assert LAB_SPEC and LAB_SPEC.loader
course_lab = importlib.util.module_from_spec(LAB_SPEC)
sys.modules[LAB_SPEC.name] = course_lab
LAB_SPEC.loader.exec_module(course_lab)


def with_flow(packet, flow_id, **changes):
    return replace(
        packet,
        flows=tuple(replace(item, **changes) if item.flow_id == flow_id else item for item in packet.flows),
    )


def test_structured_review_finds_exact_human_labelled_gaps():
    result = fixtures.service().review(fixtures.flawed_packet(), fixtures.NOW)
    assert {item.key for item in result.findings} == fixtures.expected_keys()
    assert result.receipt.disposition is review.Disposition.BLOCK


@pytest.mark.parametrize("finding_key", sorted(fixtures.expected_keys()))
def test_each_expected_finding_is_actionable(finding_key):
    result = fixtures.service().review(fixtures.flawed_packet(), fixtures.NOW)
    finding = {item.key: item for item in result.findings}[finding_key]
    assert finding.attack_path and finding.affected_asset
    assert finding.remediation
    assert finding.severity in {review.Severity.CRITICAL, review.Severity.HIGH}


def test_diagram_only_baseline_misses_non_topological_gaps():
    assert review.diagram_only_review(fixtures.flawed_packet()) == ()


def test_review_receipt_is_bound_to_packet_and_verifies():
    service = fixtures.service()
    result = service.review(fixtures.flawed_packet(), fixtures.NOW)
    assert result.receipt.packet_digest == review.packet_digest(fixtures.flawed_packet())
    assert service.verify_receipt(result.receipt)


@pytest.mark.parametrize("field,value", [
    ("tenant", "south"),
    ("packet_version", 99),
    ("disposition", review.Disposition.PASS),
    ("finding_keys", ()),
])
def test_tampered_review_receipt_does_not_verify(field, value):
    service = fixtures.service()
    receipt = service.review(fixtures.flawed_packet(), fixtures.NOW).receipt
    assert not service.verify_receipt(replace(receipt, **{field: value}))


def test_duplicate_asset_is_rejected():
    packet = fixtures.flawed_packet()
    with pytest.raises(ValueError, match="duplicate-asset"):
        fixtures.service().review(replace(packet, assets=packet.assets + (packet.assets[0],)), fixtures.NOW)


def test_duplicate_flow_is_rejected():
    packet = fixtures.flawed_packet()
    with pytest.raises(ValueError, match="duplicate-flow"):
        fixtures.service().review(replace(packet, flows=packet.flows + (packet.flows[0],)), fixtures.NOW)


def test_duplicate_evidence_is_rejected():
    packet = fixtures.flawed_packet()
    with pytest.raises(ValueError, match="duplicate-evidence"):
        fixtures.service().review(replace(packet, evidence=packet.evidence + (packet.evidence[0],)), fixtures.NOW)


def test_unknown_endpoint_is_rejected():
    packet = with_flow(fixtures.flawed_packet(), "safe-read", target="missing")
    with pytest.raises(ValueError, match="unknown-endpoint:safe-read"):
        fixtures.service().review(packet, fixtures.NOW)


def test_packet_cannot_self_assert_authenticated_tenant():
    packet = replace(fixtures.flawed_packet(), tenant="south")
    with pytest.raises(ValueError, match="tenant-scope-mismatch"):
        fixtures.service().review(packet, fixtures.NOW)


@pytest.mark.parametrize("change", [
    {"authenticated": False},
    {"tenant": "south"},
    {"subject_id": "other-flow"},
    {"source_version": 2},
    {"observed_at": fixtures.NOW + 1},
    {"expires_at": fixtures.NOW},
    {"digest": ""},
])
def test_evidence_must_be_authenticated_scoped_current_and_bound(change):
    packet = fixtures.flawed_packet()
    evidence = tuple(
        replace(item, **change) if item.evidence_id == "evidence:safe-read" else item
        for item in packet.evidence
    )
    result = fixtures.service().review(replace(packet, evidence=evidence), fixtures.NOW)
    assert "INV-CURRENT-EVIDENCE:safe-read" in {item.key for item in result.findings}


@pytest.mark.parametrize("control", sorted(review.AUTHORITY_CONTROLS))
def test_every_authority_control_is_required(control):
    packet = fixtures.remediated_packet()
    flow = next(item for item in packet.flows if item.flow_id == "safe-read")
    changed = with_flow(packet, "safe-read", controls=flow.controls - {control})
    result = fixtures.service().review(changed, fixtures.NOW)
    assert "INV-AUTHORITY-MEDIATION:safe-read" in {item.key for item in result.findings}


@pytest.mark.parametrize("control", sorted(review.EFFECT_CONTROLS))
def test_every_effect_boundary_control_is_required(control):
    packet = fixtures.remediated_packet()
    flow = next(item for item in packet.flows if item.flow_id == "direct-refund")
    changed = with_flow(packet, "direct-refund", controls=flow.controls - {control})
    result = fixtures.service().review(changed, fixtures.NOW)
    assert "INV-EFFECT-BOUNDARY:direct-refund" in {item.key for item in result.findings}


@pytest.mark.parametrize("fail_mode", ["open", "degraded"])
def test_authority_changing_path_must_fail_closed(fail_mode):
    packet = with_flow(fixtures.remediated_packet(), "safe-read", fail_mode=fail_mode)
    result = fixtures.service().review(packet, fixtures.NOW)
    assert "INV-FAIL-CLOSED:safe-read" in {item.key for item in result.findings}


def test_cross_tenant_target_is_a_critical_finding():
    result = fixtures.service().review(fixtures.flawed_packet(), fixtures.NOW)
    finding = next(item for item in result.findings if item.key == "INV-TENANT-SCOPE:cross-tenant-update")
    assert finding.severity is review.Severity.CRITICAL


def test_missing_flow_owner_routes_to_trusted_review_owner():
    result = fixtures.service().review(fixtures.flawed_packet(), fixtures.NOW)
    finding = next(item for item in result.findings if item.key == "INV-ACCOUNTABLE-OWNER:encoded-export")
    assert finding.owner == "security-architecture"


def test_encoded_capability_does_not_hide_effect_path():
    result = fixtures.service().review(fixtures.flawed_packet(), fixtures.NOW)
    assert "INV-EFFECT-BOUNDARY:encoded-export" in {item.key for item in result.findings}


def test_evidence_dependency_outage_is_unknown_not_pass():
    result = fixtures.service(evidence_available=False).review(fixtures.flawed_packet(), fixtures.NOW)
    assert result.receipt.disposition is review.Disposition.UNKNOWN
    assert result.receipt.reason == "evidence-dependency-unavailable"


def test_remediated_packet_passes_and_all_fixes_verify():
    service = fixtures.service()
    before = fixtures.flawed_packet()
    findings = service.review(before, fixtures.NOW).findings
    after = fixtures.remediated_packet()
    assert service.review(after, fixtures.NOW).receipt.disposition is review.Disposition.PASS
    outcomes = review.verify_remediations(service, before, after, findings, fixtures.NOW)
    assert len(outcomes) == len(findings)
    assert all(item.verified for item in outcomes)


def test_remediation_requires_version_advance():
    before = fixtures.flawed_packet()
    after = replace(fixtures.remediated_packet(), version=before.version)
    with pytest.raises(ValueError, match="version-not-advanced"):
        review.verify_remediations(fixtures.service(), before, after, (), fixtures.NOW)


def test_remediation_cannot_change_packet_identity():
    before = fixtures.flawed_packet()
    after = replace(fixtures.remediated_packet(), packet_id="replacement")
    with pytest.raises(ValueError, match="packet-identity-changed"):
        review.verify_remediations(fixtures.service(), before, after, (), fixtures.NOW)


def test_remediation_without_current_control_test_is_not_verified():
    service = fixtures.service()
    before = fixtures.flawed_packet()
    finding = next(item for item in service.review(before, fixtures.NOW).findings if item.flow_id == "direct-refund")
    after = fixtures.remediated_packet()
    evidence = tuple(
        replace(item, kind="diagram") if item.subject_id == "direct-refund" else item
        for item in after.evidence
    )
    outcome = review.verify_remediations(
        service, before, replace(after, evidence=evidence), (finding,), fixtures.NOW
    )[0]
    assert not outcome.verified
    assert outcome.reason == "missing-current-control-test"


def test_remediation_cannot_verify_when_new_regression_blocks_packet():
    service = fixtures.service()
    before = fixtures.flawed_packet()
    finding = next(item for item in service.review(before, fixtures.NOW).findings if item.flow_id == "direct-refund")
    after = with_flow(fixtures.remediated_packet(), "safe-read", fail_mode="open")
    outcome = review.verify_remediations(service, before, after, (finding,), fixtures.NOW)[0]
    assert not outcome.verified
    assert outcome.reason == "review-not-pass:block"


def test_schema_adapter_accepts_fixture_packet():
    packet = fixtures.flawed_packet()
    assert parse_packet(asdict(packet)) == packet


def test_schema_adapter_rejects_extra_fields():
    payload = asdict(fixtures.flawed_packet())
    payload["trusted"] = True
    with pytest.raises(ValidationError):
        parse_packet(payload)


def test_schema_adapter_rejects_coerced_boolean():
    payload = asdict(fixtures.flawed_packet())
    payload["flows"][0]["effect"] = "false"
    with pytest.raises(ValidationError):
        parse_packet(payload)


def test_schema_adapter_rejects_unknown_fail_mode():
    payload = asdict(fixtures.flawed_packet())
    payload["flows"][0]["fail_mode"] = "hope"
    with pytest.raises(ValidationError):
        parse_packet(payload)


def test_metrics_report_exact_numerators_and_denominators():
    evaluation = course_lab.evaluate_workshop()
    assert evaluation.finding_precision == course_lab.Metric(7, 7, 1.0)
    assert evaluation.severe_gap_recall == course_lab.Metric(4, 4, 1.0)
    assert evaluation.naive_severe_gap_recall == course_lab.Metric(0, 4, 0.0)
    assert evaluation.remediation_quality == course_lab.Metric(7, 7, 1.0)
    assert evaluation.reviewer_agreement == course_lab.Metric(8, 10, 0.8)


def test_empty_metric_population_is_not_fabricated_as_zero():
    assert course_lab.metric(0, 0).value is None


def test_reviewer_finding_outside_fixed_universe_is_rejected():
    with pytest.raises(ValueError, match="finding-outside-review-universe"):
        course_lab.reviewer_agreement({"invented"}, set(), set())


def test_lab_runs_top_to_bottom():
    result = course_lab.run_lab()
    assert result["final_receipt"]["disposition"] is review.Disposition.PASS
