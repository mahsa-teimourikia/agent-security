"""Focused invariants for Advanced 08 red teaming and adversarial evaluation."""

from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
from math import nan
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
COURSE = ROOT / "curriculum/roadmap/advanced/08-agent-red-teaming-and-adversarial-evaluation"


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
    return load("advanced_08_campaign", COURSE / "campaign.py")


@pytest.fixture()
def campaign(lab):
    return lab.build_campaign(now=datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc))


def safe_results(lab, campaign):
    return lab.run_campaign(campaign, lab.ControlProfile("hardened"))


def test_hardened_campaign_is_complete_and_ready(lab, campaign) -> None:
    report = lab.evaluate_campaign(campaign, safe_results(lab, campaign))
    assert report.decision is lab.Decision.READY
    assert report.attack_success_rate == report.boundary_violation_rate == report.valid_block_rate == 0
    assert report.trace_coverage == report.attempt_coverage == report.category_coverage == 1
    assert report.failure_containment_rate == 1


def test_campaign_digest_changes_with_target_policy_catalog_and_fixture(lab, campaign) -> None:
    digests = {
        campaign.digest,
        replace(campaign, binding=replace(campaign.binding, target_version="release-19")).digest,
        replace(campaign, binding=replace(campaign.binding, policy_version="policy-v13")).digest,
        replace(campaign, binding=replace(campaign.binding, tool_catalog_version="catalog-v9")).digest,
        replace(campaign, fixtures=(replace(campaign.fixtures[0], version="1.1"), *campaign.fixtures[1:])).digest,
    }
    assert len(digests) == 5


def test_all_four_populations_are_required(lab, campaign) -> None:
    for population in lab.Population:
        reduced = replace(campaign, fixtures=tuple(item for item in campaign.fixtures if item.population is not population))
        with pytest.raises(ValueError, match="valid, attack, boundary, and failure"):
            lab.evaluate_campaign(reduced, [])


def test_duplicate_fixture_identifiers_are_rejected(lab, campaign) -> None:
    duplicate = replace(campaign, fixtures=(*campaign.fixtures, campaign.fixtures[0]))
    with pytest.raises(ValueError, match="fixture identifiers"):
        lab.evaluate_campaign(duplicate, [])


def test_attack_rate_uses_attack_cases_not_all_cases(lab, campaign) -> None:
    results = lab.run_campaign(campaign, lab.ControlProfile("unsafe", vulnerable_fixtures=frozenset({"mcp-001"})))
    report = lab.evaluate_campaign(campaign, results)
    assert report.attack_success_rate == pytest.approx(1 / 6)
    assert report.attack_attempt_success_rate == pytest.approx(2 / 12)
    assert report.severe_successes == 1


def test_any_successful_attempt_fails_the_attack_case(lab, campaign) -> None:
    results = safe_results(lab, campaign)
    index = next(i for i, item in enumerate(results) if item.fixture_id == "inj-001")
    fixture = next(item for item in campaign.fixtures if item.fixture_id == "inj-001")
    results[index] = lab.result_for(campaign, fixture, 1, outcome=lab.Outcome.ALLOWED, forbidden_effect=True)
    report = lab.evaluate_campaign(campaign, results)
    assert report.attack_success_rate == pytest.approx(1 / 6)
    assert report.attack_attempt_success_rate == pytest.approx(1 / 12)


def test_valid_block_rate_has_a_valid_only_denominator(lab, campaign) -> None:
    results = lab.run_campaign(campaign, lab.ControlProfile("overblock", overblocked_valid_fixtures=frozenset({"valid-read-001"})))
    report = lab.evaluate_campaign(campaign, results)
    assert report.valid_block_rate == 0.5
    assert report.attack_success_rate == 0
    assert "valid-block-threshold" in report.blockers


def test_forbidden_effect_beats_a_claimed_block(lab, campaign) -> None:
    results = safe_results(lab, campaign)
    fixture = next(item for item in campaign.fixtures if item.fixture_id == "scope-001")
    index = next(i for i, item in enumerate(results) if item.fixture_id == fixture.fixture_id)
    results[index] = lab.result_for(campaign, fixture, 1, outcome=lab.Outcome.BLOCKED, forbidden_effect=True)
    report = lab.evaluate_campaign(campaign, results)
    assert report.decision is lab.Decision.BLOCKED
    assert any(item == "attack-success:scope-001" for item in report.blockers)


@pytest.mark.parametrize("field,value,prefix", [
    ("target_version", "release-17", "binding-target"),
    ("policy_version", "policy-v11", "binding-policy"),
    ("tool_catalog_version", "catalog-v7", "binding-catalog"),
    ("environment", "production", "binding-environment"),
    ("campaign_digest", "0" * 64, "binding-digest"),
])
def test_stale_or_foreign_bindings_are_incomplete(lab, campaign, field: str, value: str, prefix: str) -> None:
    results = safe_results(lab, campaign)
    results[0] = replace(results[0], **{field: value})
    report = lab.evaluate_campaign(campaign, results)
    assert report.decision is lab.Decision.INCOMPLETE
    assert any(reason.startswith(prefix) for reason in report.incomplete_reasons)


def test_foreign_and_duplicate_results_are_rejected(lab, campaign) -> None:
    results = safe_results(lab, campaign)
    with pytest.raises(ValueError, match="undeclared"):
        lab.evaluate_campaign(campaign, [replace(results[0], fixture_id="foreign"), *results[1:]])
    with pytest.raises(ValueError, match="unique"):
        lab.evaluate_campaign(campaign, [*results, results[0]])


@pytest.mark.parametrize("state,count", [
    ("HARNESS_ERROR", "harness_errors"),
    ("TARGET_ERROR", "target_errors"),
])
def test_execution_errors_are_incomplete_not_safe_blocks(lab, campaign, state: str, count: str) -> None:
    fixture = campaign.fixtures[0]
    results = safe_results(lab, campaign)
    index = next(i for i, item in enumerate(results) if item.fixture_id == fixture.fixture_id)
    results[index] = lab.result_for(campaign, fixture, 1, execution_state=getattr(lab.ExecutionState, state))
    report = lab.evaluate_campaign(campaign, results)
    assert report.decision is lab.Decision.INCOMPLETE
    assert getattr(report, count) == 1
    assert report.attack_success_rate == 0


def test_missing_trace_is_incomplete_not_a_pass(lab, campaign) -> None:
    results = lab.run_campaign(campaign, lab.ControlProfile("blind", missing_trace_fixtures=frozenset({"inj-001"})))
    report = lab.evaluate_campaign(campaign, results)
    assert report.decision is lab.Decision.INCOMPLETE
    assert report.trace_coverage < 1
    assert any(reason.startswith("untraceable:inj-001") for reason in report.incomplete_reasons)


def test_trace_sequence_tenant_and_redaction_are_verified(lab, campaign) -> None:
    for mutation in (
        lambda event: replace(event, sequence=9),
        lambda event: replace(event, tenant_id="tenant-b"),
        lambda event: replace(event, redacted=False),
        lambda event: replace(event, evidence_ids=()),
    ):
        results = safe_results(lab, campaign)
        first = results[0]
        results[0] = replace(first, trace=(mutation(first.trace[0]), *first.trace[1:]))
        assert lab.evaluate_campaign(campaign, results).decision is lab.Decision.INCOMPLETE


def test_control_mismatch_blocks_even_with_complete_trace(lab, campaign) -> None:
    results = safe_results(lab, campaign)
    results[0] = replace(results[0], observed_control="model-claim")
    report = lab.evaluate_campaign(campaign, results)
    assert report.decision is lab.Decision.BLOCKED
    assert any(item.startswith("control-mismatch") for item in report.blockers)


def test_boundary_violation_has_its_own_rate(lab, campaign) -> None:
    results = lab.run_campaign(campaign, lab.ControlProfile("boundary", vulnerable_fixtures=frozenset({"boundary-budget-001"})))
    report = lab.evaluate_campaign(campaign, results)
    assert report.boundary_violation_rate == 0.5
    assert report.attack_success_rate == 0


def test_failure_population_measures_containment(lab, campaign) -> None:
    results = safe_results(lab, campaign)
    fixture = next(item for item in campaign.fixtures if item.fixture_id == "failure-mcp-001")
    index = next(i for i, item in enumerate(results) if item.fixture_id == fixture.fixture_id)
    results[index] = lab.result_for(campaign, fixture, 1, outcome=lab.Outcome.ALLOWED, forbidden_effect=True)
    report = lab.evaluate_campaign(campaign, results)
    assert report.failure_containment_rate == 0.5
    assert "failure-not-contained:failure-mcp-001" in report.blockers


def test_step_and_total_cost_budgets_are_enforced(lab, campaign) -> None:
    results = safe_results(lab, campaign)
    fixture = campaign.fixtures[0]
    results[0] = replace(results[0], steps_used=fixture.max_steps + 1)
    report = lab.evaluate_campaign(campaign, results)
    assert any(item.startswith("step-budget") for item in report.blockers)
    expensive = [replace(item, cost_units=campaign.maximum_cost_units) for item in results]
    assert "campaign-cost-budget" in lab.evaluate_campaign(campaign, expensive).blockers


def test_open_severe_finding_blocks_and_verified_regression_closes(lab, campaign) -> None:
    finding = lab.finding_from_failure(campaign, "mcp-001")
    blocked = lab.evaluate_campaign(campaign, safe_results(lab, campaign), findings=[finding])
    assert blocked.decision is lab.Decision.BLOCKED
    closed = lab.evaluate_campaign(campaign, safe_results(lab, campaign), findings=[lab.close_finding(finding)])
    assert closed.decision is lab.Decision.READY


def test_fake_mitigation_without_regression_is_incomplete(lab, campaign) -> None:
    finding = replace(lab.finding_from_failure(campaign, "mcp-001"), status=lab.FindingStatus.MITIGATED)
    report = lab.evaluate_campaign(campaign, safe_results(lab, campaign), findings=[finding])
    assert report.decision is lab.Decision.INCOMPLETE
    assert any(item.startswith("finding-evidence") for item in report.incomplete_reasons)


@pytest.mark.parametrize("value", [nan, -0.1, 1.1, True])
def test_invalid_metric_thresholds_fail_closed(lab, campaign, value) -> None:
    with pytest.raises(ValueError, match="finite"):
        lab.evaluate_campaign(campaign, [], policy=lab.GatePolicy(maximum_valid_block_rate=value))


def test_attempt_and_step_limits_are_bounded(lab, campaign) -> None:
    too_many = replace(campaign, fixtures=(replace(campaign.fixtures[0], attempts_required=9), *campaign.fixtures[1:]))
    with pytest.raises(ValueError, match="attempts"):
        lab.evaluate_campaign(too_many, [])
    too_deep = replace(campaign, fixtures=(replace(campaign.fixtures[0], max_steps=99), *campaign.fixtures[1:]))
    with pytest.raises(ValueError, match="max_steps"):
        lab.evaluate_campaign(too_deep, [])


def test_demo_preserves_ready_blocked_incomplete_distinction(lab) -> None:
    reports = lab.demo()
    assert [item.decision for item in reports] == [lab.Decision.READY, lab.Decision.BLOCKED, lab.Decision.INCOMPLETE]


def test_pyrit_adapter_fails_with_actionable_message_when_extra_absent(lab) -> None:
    adapter = load("advanced_08_pyrit_adapter", COURSE / "pyrit_adapter.py")
    if adapter.pyrit_available():
        pytest.skip("optional PyRIT extra is installed")
    with pytest.raises(RuntimeError, match="redteam"):
        adapter.PyRITSupportAgentTarget(campaign=lab.build_campaign(), profile=lab.ControlProfile("safe"))
