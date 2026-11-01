"""Focused invariants for Advanced 10 threat hunting and anomaly detection."""
from dataclasses import replace
import importlib.util
from math import inf, nan
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
COURSE = ROOT / "curriculum/roadmap/advanced/10-threat-hunting-and-behavioral-anomaly-detection"


def load(name: str, path: Path):
    sys.path.insert(0, str(COURSE))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lab():
    return load("advanced_10_threat_hunting", COURSE / "threat_hunting.py")


def case_by_id(lab, case_id: str):
    return next(item for item in lab.course_cases() if item.case_id == case_id)


def hunt(lab, case_id: str, mutate=lambda events: events, **kwargs):
    case = case_by_id(lab, case_id)
    return lab.hunt_case(case, tuple(mutate(list(lab.events_for(case)))), **kwargs)


def test_hardened_suite_uses_all_populations_and_finds_labeled_attacks(lab) -> None:
    report = lab.evaluate_suite()
    assert {item.population for item in report.results} == set(lab.Population)
    assert report.precision == report.recall == 1
    assert report.macro_tenant_false_positive_rate == 0


def test_valid_and_boundary_sequences_do_not_create_hypotheses(lab) -> None:
    for case_id in ("valid-support", "valid-batch", "valid-approval", "boundary-threshold"):
        assert hunt(lab, case_id).state is lab.HuntState.NO_HYPOTHESIS


def test_visibility_and_dependency_failures_are_unknown(lab) -> None:
    for case_id in ("failure-gap", "failure-detector"):
        assert hunt(lab, case_id).state is lab.HuntState.UNKNOWN


@pytest.mark.parametrize("case_id,rule_id", [
    ("attack-scope", "AGENT-SCOPE-PROBE"),
    ("attack-slow-scope", "AGENT-SCOPE-PROBE"),
    ("attack-fanout", "AGENT-FANOUT-DRIFT"),
    ("attack-approval", "AGENT-APPROVAL-PRESSURE"),
    ("attack-egress", "AGENT-EGRESS-DRIFT"),
    ("attack-encoded-egress", "AGENT-EGRESS-DRIFT"),
])
def test_every_attack_family_has_evidence_linked_hypothesis(lab, case_id: str, rule_id: str) -> None:
    result = hunt(lab, case_id)
    hypothesis = next(item for item in result.hypotheses if item.rule_id == rule_id)
    assert result.state is lab.HuntState.HYPOTHESIS
    assert hypothesis.evidence_ids
    assert hypothesis.detected_at_ms >= hypothesis.first_suspicious_ms


def test_naive_exact_match_detector_misses_sequence_and_encoded_attacks(lab) -> None:
    naive = lab.evaluate_suite(naive=True)
    hardened = lab.evaluate_suite()
    assert naive.recall < hardened.recall == 1
    assert naive.false_positives == 0


def test_scope_probe_is_correlated_across_runs_within_window(lab) -> None:
    result = hunt(lab, "attack-slow-scope")
    assert result.state is lab.HuntState.HYPOTHESIS
    assert len({event.run_id for event in lab.events_for(case_by_id(lab, "attack-slow-scope"))}) == 4


def test_events_older_than_the_tenant_window_are_not_aggregated(lab) -> None:
    def stale_first(events):
        events[:] = [replace(item, event_time_ms=item.event_time_ms + 1_000_000) for item in events]
        latest = max(item.event_time_ms for item in events)
        events[0] = replace(events[0], event_time_ms=latest - 900_001)
        return events

    result = hunt(lab, "attack-scope", stale_first)
    assert result.state is lab.HuntState.NO_HYPOTHESIS
    assert len(result.features.event_ids) == 3


def test_exact_threshold_is_allowed_and_one_more_is_detected(lab) -> None:
    assert hunt(lab, "boundary-threshold").state is lab.HuntState.NO_HYPOTHESIS
    assert hunt(lab, "attack-scope").state is lab.HuntState.HYPOTHESIS


def test_duplicate_resource_does_not_inflate_unique_breadth(lab) -> None:
    def duplicate_resource(events):
        events[1] = replace(events[1], attributes={**events[1].attributes, "resource_id": "sensitive-1"})
        return events

    result = hunt(lab, "attack-scope", duplicate_resource)
    assert result.state is lab.HuntState.NO_HYPOTHESIS
    assert len(result.features.sensitive_resources) == 3


def test_tenant_normalized_baseline_avoids_global_fanout_threshold(lab) -> None:
    case_b = case_by_id(lab, "valid-batch")
    events_b = lab.events_for(case_b)
    assert lab.hunt_case(case_b, events_b).state is lab.HuntState.NO_HYPOTHESIS

    case_a = replace(case_b, tenant_id="tenant-a")
    events_a = tuple(replace(item, tenant_id="tenant-a") for item in events_b)
    assert lab.hunt_case(case_a, events_a).state is lab.HuntState.HYPOTHESIS


def test_cross_tenant_events_are_never_aggregated(lab) -> None:
    def foreign(events):
        events[-1] = replace(events[-1], tenant_id="tenant-b")
        return events

    assert hunt(lab, "attack-scope", foreign).state is lab.HuntState.UNKNOWN


def test_cross_subject_events_are_never_aggregated(lab) -> None:
    def foreign(events):
        events[-1] = replace(events[-1], subject_id="another-user")
        return events

    assert hunt(lab, "attack-scope", foreign).state is lab.HuntState.UNKNOWN


def test_foreign_case_event_is_unknown(lab) -> None:
    def foreign(events):
        events[-1] = replace(events[-1], case_id="different-case")
        return events

    assert hunt(lab, "attack-scope", foreign).state is lab.HuntState.UNKNOWN


@pytest.mark.parametrize("value,expected", [
    ("HTTPS://SUPPORT.EXAMPLE./api", "support.example"),
    ("https://exfіl.example/upload", "xn--exfl-n9d.example"),
])
def test_destination_canonicalization_handles_case_dot_and_idna(lab, value: str, expected: str) -> None:
    assert lab.canonical_host(value) == expected


@pytest.mark.parametrize("value", [
    "/relative/path",
    "https://trusted.example@evil.example/path",
    "not-a-url",
])
def test_destination_canonicalization_rejects_ambiguous_urls(lab, value: str) -> None:
    with pytest.raises(ValueError, match="absolute URL"):
        lab.canonical_host(value)


def test_unicode_lookalike_destination_does_not_bypass_baseline(lab) -> None:
    result = hunt(lab, "attack-encoded-egress")
    assert result.features.unknown_destinations == ("xn--exfl-n9d.example",)
    assert result.alerted


def test_effect_before_approval_denials_is_not_called_approval_pressure(lab) -> None:
    def reorder(events):
        events[-1] = replace(events[-1], event_time_ms=0)
        return events

    result = hunt(lab, "attack-approval", reorder)
    assert result.state is lab.HuntState.NO_HYPOTHESIS
    assert result.features.effect_after_denials is False


def test_denials_without_effect_do_not_create_hypothesis(lab) -> None:
    assert hunt(lab, "valid-approval").state is lab.HuntState.NO_HYPOTHESIS


def test_duplicate_event_ids_make_result_unknown(lab) -> None:
    def duplicate(events):
        events[-1] = replace(events[-1], event_id=events[0].event_id)
        return events

    assert hunt(lab, "attack-scope", duplicate).state is lab.HuntState.UNKNOWN


def test_missing_evidence_never_becomes_no_hypothesis(lab) -> None:
    def remove_evidence(events):
        events[0] = replace(events[0], evidence_ids=())
        return events

    result = hunt(lab, "valid-support", remove_evidence)
    assert result.state is lab.HuntState.UNKNOWN
    assert result.evidence_coverage == pytest.approx(0.5)


def test_blank_evidence_identifier_is_not_coverage(lab) -> None:
    def blank_evidence(events):
        events[0] = replace(events[0], evidence_ids=("",))
        return events

    assert hunt(lab, "attack-egress", blank_evidence).state is lab.HuntState.UNKNOWN


def test_missing_required_feature_attribute_is_unknown(lab) -> None:
    def malformed(events):
        events[0] = replace(events[0], attributes={"sensitivity": "restricted"})
        return events

    assert hunt(lab, "attack-scope", malformed).state is lab.HuntState.UNKNOWN


def test_malformed_egress_event_is_unknown(lab) -> None:
    def malformed(events):
        events[0] = replace(events[0], attributes={"destination": 42})
        return events

    assert hunt(lab, "attack-egress", malformed).state is lab.HuntState.UNKNOWN


def test_unknown_tenant_profile_is_unknown(lab) -> None:
    case = case_by_id(lab, "valid-support")
    assert lab.hunt_case(case, lab.events_for(case), profiles={}).state is lab.HuntState.UNKNOWN


def test_metrics_use_declared_denominators(lab) -> None:
    report = lab.evaluate_suite()
    assert len(report.results) == 12
    assert report.true_positives == 6
    assert report.false_positives == report.false_negatives == 0
    assert report.alerts_per_100_cases == 50
    assert report.unknown_rate == pytest.approx(2 / 12)
    assert report.tenant_false_positive_rates == {"tenant-a": 0.0, "tenant-b": 0.0}


def test_detection_latency_uses_fixture_event_time(lab) -> None:
    report = lab.evaluate_suite()
    assert report.mean_detection_latency_ms == pytest.approx(640_000 / 6)


def test_disposition_requires_accountable_analyst_and_evidence(lab) -> None:
    hypothesis = hunt(lab, "attack-egress").hypotheses[0]
    with pytest.raises(ValueError, match="accountable analyst"):
        lab.disposition(hypothesis, lab.Disposition.CONFIRMED, "", ["receipt-1"])
    with pytest.raises(ValueError, match="supporting evidence"):
        lab.disposition(hypothesis, lab.Disposition.CONFIRMED, "analyst-7", [])

    completed = lab.disposition(
        hypothesis, lab.Disposition.CONFIRMED, " analyst-7 ", ["receipt-1", "receipt-1"],
    )
    assert completed.analyst_id == "analyst-7"
    assert completed.disposition_evidence_ids == ("receipt-1",)
    assert not hasattr(completed, "response_authorized")


def test_open_is_not_a_completed_disposition(lab) -> None:
    hypothesis = hunt(lab, "attack-egress").hypotheses[0]
    with pytest.raises(ValueError, match="cannot remain open"):
        lab.disposition(hypothesis, lab.Disposition.OPEN, "analyst-7", ["receipt-1"])


def test_suite_requires_all_populations_and_unique_ids(lab) -> None:
    cases = lab.course_cases()
    with pytest.raises(ValueError, match="valid, attack"):
        lab.evaluate_suite([item for item in cases if item.population is not lab.Population.FAILURE])
    with pytest.raises(ValueError, match="unique"):
        lab.evaluate_suite((*cases, cases[0]))


@pytest.mark.parametrize("value", [nan, inf, -0.1, 1.1, True, "0.5"])
def test_invalid_rates_fail_closed(lab, value) -> None:
    with pytest.raises(ValueError, match="finite number"):
        lab.validate_rate(value)


def test_real_pysigma_adapter_parses_and_converts_rule() -> None:
    adapter = load("advanced_10_sigma_adapter", COURSE / "sigma_adapter.py")
    parsed = adapter.parse_and_convert(COURSE / "agent_egress_drift.yml")
    assert parsed.rule_id == "418b7d3f-b536-45ad-a896-8df45f7617dd"
    assert parsed.status == "experimental"
    assert parsed.level == "high"
    assert parsed.query == 'event_type="egress" and destination_trust="unknown"'


def test_pysigma_adapter_rejects_multiple_or_invalid_documents(tmp_path: Path) -> None:
    adapter = load("advanced_10_sigma_adapter_invalid", COURSE / "sigma_adapter.py")
    invalid = tmp_path / "invalid.yml"
    invalid.write_text("title: missing required fields\n", encoding="utf-8")
    with pytest.raises(Exception):
        adapter.parse_and_convert(invalid)
