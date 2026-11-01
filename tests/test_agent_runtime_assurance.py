"""Focused invariants for Advanced 09 observability and runtime assurance."""
from dataclasses import replace
import importlib.util
from math import nan
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
COURSE = ROOT / "curriculum/roadmap/advanced/09-agent-security-observability-and-runtime-assurance"


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
    return load("advanced_09_runtime_assurance", COURSE / "runtime_assurance.py")


def case_by_id(lab, case_id: str):
    return next(item for item in lab.course_cases() if item.case_id == case_id)


def assess(lab, case_id: str, mutate=lambda events: events):
    case = case_by_id(lab, case_id)
    binding, events = lab.events_for(case)
    return lab.assess_case(case, binding, tuple(mutate(list(events))))


def test_hardened_suite_uses_all_four_populations_and_finds_labeled_violations(lab) -> None:
    report = lab.evaluate_suite()
    assert {item.population for item in report.assessments} == set(lab.Population)
    assert report.precision == report.recall == 1
    assert report.valid_false_positive_rate == 0


def test_valid_operations_remain_healthy(lab) -> None:
    for case_id in ("valid-read", "valid-refund"):
        assert assess(lab, case_id).state is lab.AssuranceState.HEALTHY


def test_failure_cases_are_unknown_not_healthy(lab) -> None:
    for case_id in ("failure-collector", "failure-missing-end"):
        assert assess(lab, case_id).state is lab.AssuranceState.UNKNOWN


@pytest.mark.parametrize("case_id,code", [
    ("attack-cross-tenant", "cross-tenant-effect"),
    ("attack-orphan-effect", "orphan-effect"),
    ("attack-secret", "telemetry-sensitive-data"),
    ("attack-stale-policy", "binding-mismatch"),
    ("boundary-duplicate", "duplicate-effect"),
    ("boundary-budget", "budget-exceeded"),
])
def test_each_labeled_violation_has_evidence_linked_finding(lab, case_id: str, code: str) -> None:
    assessment = assess(lab, case_id)
    assert assessment.state is lab.AssuranceState.VIOLATED
    finding = next(item for item in assessment.findings if item.code == code)
    assert finding.evidence_ids
    assert finding.detected_at_ms >= finding.violation_at_ms


def test_untrusted_policy_claim_does_not_authorize_effect(lab) -> None:
    def mutate(events):
        return [replace(item, authority=lab.Authority.UNTRUSTED, source="agent")
                if item.kind is lab.EventKind.POLICY_DECISION else item for item in events]
    assessment = assess(lab, "valid-read", mutate)
    assert assessment.state is lab.AssuranceState.VIOLATED
    assert assessment.orphan_effects == 1


def test_untrusted_effect_claim_is_not_counted_as_observed_effect(lab) -> None:
    def mutate(events):
        return [replace(item, authority=lab.Authority.UNTRUSTED, source="agent")
                if item.kind is lab.EventKind.EFFECT_OBSERVED else item for item in events]
    assessment = assess(lab, "valid-read", mutate)
    assert assessment.state.value == lab.AssuranceState.HEALTHY.value
    assert assessment.orphan_effects == 0


def test_forged_authoritative_source_makes_evidence_incomplete(lab) -> None:
    def mutate(events):
        return [replace(item, source="agent") if item.kind is lab.EventKind.POLICY_DECISION else item for item in events]
    assert assess(lab, "valid-read", mutate).state is lab.AssuranceState.VIOLATED


@pytest.mark.parametrize("field", ["binding_digest", "operation_id", "subject_id"])
def test_stale_or_foreign_binding_is_not_admitted(lab, field: str) -> None:
    def mutate(events):
        events[2] = replace(events[2], **{field: "foreign"})
        return events
    assessment = assess(lab, "valid-read", mutate)
    assert assessment.state is lab.AssuranceState.VIOLATED
    assert any(item.code == "binding-mismatch" for item in assessment.findings)


def test_cross_tenant_effect_uses_authenticated_binding_not_event_claim(lab) -> None:
    assessment = assess(lab, "attack-cross-tenant")
    assert any(item.code == "cross-tenant-effect" for item in assessment.findings)


def test_missing_policy_decision_cannot_be_replaced_by_agent_proposal(lab) -> None:
    assessment = assess(lab, "attack-orphan-effect")
    assert assessment.decision_covered is False
    assert assessment.orphan_effects == 1


def test_consequential_effect_requires_consumed_approval_before_effect(lab) -> None:
    def remove_approval(events):
        return [item for item in events if item.kind is not lab.EventKind.APPROVAL_CONSUMED]
    assessment = assess(lab, "valid-refund", remove_approval)
    assert assessment.state is lab.AssuranceState.VIOLATED
    assert any(item.code == "orphan-effect" for item in assessment.findings)


def test_approval_after_effect_does_not_authorize_effect(lab) -> None:
    case = case_by_id(lab, "valid-refund")
    binding, events = lab.events_for(case)
    approval = next(item for item in events if item.kind is lab.EventKind.APPROVAL_CONSUMED)
    effect = next(item for item in events if item.kind is lab.EventKind.EFFECT_OBSERVED)
    swapped = [replace(item, sequence=approval.sequence) if item is effect else
               replace(item, sequence=effect.sequence) if item is approval else item for item in events]
    swapped = tuple(sorted(swapped, key=lambda item: item.sequence))
    assessment = lab.assess_case(case, binding, swapped)
    assert any(item.code == "orphan-effect" for item in assessment.findings)


def test_duplicate_event_identifier_is_incomplete(lab) -> None:
    def duplicate(events):
        events.append(events[-1])
        return events
    assert assess(lab, "valid-read", duplicate).state is lab.AssuranceState.UNKNOWN


def test_out_of_order_sequence_is_incomplete(lab) -> None:
    def mutate(events):
        events[1] = replace(events[1], sequence=9)
        return events
    assert assess(lab, "valid-read", mutate).state is lab.AssuranceState.UNKNOWN


def test_non_monotonic_event_time_is_incomplete(lab) -> None:
    def mutate(events):
        events[2] = replace(events[2], emitted_at_ms=1)
        return events
    assert assess(lab, "valid-read", mutate).state is lab.AssuranceState.UNKNOWN


@pytest.mark.parametrize("key", ["access_token", "authorization", "prompt", "chain_of_thought", "custom_unclassified"])
def test_sensitive_or_unclassified_attributes_are_violations(lab, key: str) -> None:
    def mutate(events):
        events[1] = replace(events[1], attributes={**events[1].attributes, key: "unsafe"})
        return events
    assessment = assess(lab, "valid-read", mutate)
    assert assessment.state is lab.AssuranceState.VIOLATED
    assert assessment.redaction_failures == 1


def test_sensitive_value_cannot_hide_in_target_digest_field(lab) -> None:
    def mutate(events):
        events[1] = replace(events[1], attributes={**events[1].attributes, "target_digest": "secret-token-value"})
        return events
    assessment = assess(lab, "valid-read", mutate)
    assert assessment.state is lab.AssuranceState.VIOLATED
    assert assessment.redaction_failures == 1


def test_empty_effect_identifier_is_a_violation(lab) -> None:
    def mutate(events):
        index = next(i for i, item in enumerate(events) if item.kind is lab.EventKind.EFFECT_OBSERVED)
        events[index] = replace(events[index], attributes={**events[index].attributes, "effect_id": ""})
        return events
    assert any(item.code == "duplicate-effect" for item in assess(lab, "valid-read", mutate).findings)


@pytest.mark.parametrize("steps,limit", [(5, 4), (1, True), ("5", 5)])
def test_budget_values_are_checked_by_application_owned_monitor(lab, steps, limit) -> None:
    def mutate(events):
        index = next(i for i, item in enumerate(events) if item.kind is lab.EventKind.BUDGET_SNAPSHOT)
        events[index] = replace(events[index], attributes={"steps_used": steps, "step_limit": limit})
        return events
    assessment = assess(lab, "valid-read", mutate)
    assert assessment.state in {lab.AssuranceState.VIOLATED, lab.AssuranceState.UNKNOWN}


def test_metrics_use_correct_labeled_denominators(lab) -> None:
    report = lab.evaluate_suite()
    assert len(report.assessments) == 10
    assert report.unknown_rate == pytest.approx(2 / 10)
    assert report.complete_trace_rate == pytest.approx(6 / 10)
    assert report.valid_false_positive_rate == 0 / 2


def test_naive_monitor_misses_binding_and_redaction_violations(lab) -> None:
    report = lab.evaluate_suite(naive=True)
    assert report.recall < 1
    assert report.precision == 1


def test_detection_latency_uses_event_timestamps_not_wall_clock_sleep(lab) -> None:
    report = lab.evaluate_suite()
    assert report.mean_detection_latency_ms == 0


def test_response_is_bounded_and_idempotent(lab) -> None:
    assessment = assess(lab, "attack-cross-tenant")
    first = lab.response_for(assessment)
    second = lab.response_for(assessment)
    assert first == second
    assert first.action is lab.ResponseAction.CONTAIN
    assert len(first.idempotency_key) == 64


def test_unknown_state_alerts_instead_of_claiming_containment(lab) -> None:
    receipt = lab.response_for(assess(lab, "failure-collector"))
    assert receipt.action is lab.ResponseAction.ALERT


def test_healthy_state_observes_without_privileged_action(lab) -> None:
    assert lab.response_for(assess(lab, "valid-read")).action is lab.ResponseAction.OBSERVE


def test_binding_digest_changes_with_every_security_version(lab) -> None:
    binding = lab.default_binding("valid-read")
    digests = {
        binding.digest,
        replace(binding, policy_version="policy-v13").digest,
        replace(binding, tool_catalog_version="catalog-v9").digest,
        replace(binding, model_version="model-v5").digest,
        replace(binding, environment="production").digest,
    }
    assert len(digests) == 5


def test_suite_requires_all_populations_and_unique_ids(lab) -> None:
    cases = lab.course_cases()
    with pytest.raises(ValueError, match="all four|valid, attack"):
        lab.evaluate_suite([item for item in cases if item.population is not lab.Population.FAILURE])
    with pytest.raises(ValueError, match="unique"):
        lab.evaluate_suite((*cases, cases[0]))


@pytest.mark.parametrize("value", [nan, -0.1, 1.1, True, "0.5"])
def test_invalid_thresholds_fail_closed(lab, value) -> None:
    with pytest.raises(ValueError, match="finite"):
        lab.validate_threshold(value)


def test_real_opentelemetry_adapter_round_trips_valid_case(lab) -> None:
    adapter = load("advanced_09_otel_adapter", COURSE / "otel_adapter.py")
    assessment = adapter.run_adapter("valid-refund")
    assert assessment.state.value == lab.AssuranceState.HEALTHY.value
    assert assessment.completeness == 1


def test_opentelemetry_transport_does_not_upgrade_untrusted_authority(lab) -> None:
    adapter = load("advanced_09_otel_adapter_authority", COURSE / "otel_adapter.py")
    case = case_by_id(lab, "valid-read")
    capture, binding = adapter.emit_case(case)
    try:
        events = adapter.spans_to_events(capture.spans(), capture.authority_by_event_id)
    finally:
        capture.shutdown()
    proposal = next(item for item in events if item.kind.value == lab.EventKind.AGENT_PROPOSAL.value)
    assert proposal.authority.value == lab.Authority.UNTRUSTED.value
    assert adapter.lab.assess_case(case, binding, events).state is adapter.lab.AssuranceState.HEALTHY


def test_opentelemetry_claimed_authority_is_ignored_without_trusted_context(lab) -> None:
    adapter = load("advanced_09_otel_adapter_no_authority", COURSE / "otel_adapter.py")
    case = case_by_id(lab, "valid-read")
    capture, _ = adapter.emit_case(case)
    try:
        events = adapter.spans_to_events(capture.spans())
    finally:
        capture.shutdown()
    assert events
    assert all(item.authority is adapter.lab.Authority.UNTRUSTED for item in events)
