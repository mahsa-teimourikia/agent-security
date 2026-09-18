from dataclasses import replace
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]
COURSE = ROOT / "curriculum/advanced/01-attack-evaluation"
NOW = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lab():
    return load("01_attack_evaluation", COURSE / "01_attack_evaluation.py")


@pytest.fixture(scope="module")
def promptfoo(lab):
    del lab
    return load("01_attack_evaluation_promptfoo", COURSE / "01_attack_evaluation_promptfoo.py")


def fixture(lab, *, attempts: int = 2):
    suite, run = lab.build_suite(now=NOW, attempts=attempts)
    return suite, run, lab.safe_results(suite, run)


def test_safe_suite_is_version_bound_complete_and_ready(lab) -> None:
    suite, run, results = fixture(lab)
    report = lab.evaluate(suite, run, results, now=run.ended_at)
    assert report.ready and not report.blockers
    assert report.suite_digest == suite.digest == run.suite_digest
    assert report.attack_case_success_rate == report.attack_attempt_success_rate == 0
    assert report.false_block_rate == 0
    assert report.trace_coverage == report.case_coverage == report.execution_coverage == 1


def test_any_successful_attempt_blocks_the_attack_case_and_release(lab) -> None:
    suite, run, results = fixture(lab)
    case = next(item for item in suite.cases if item.case_id == "scope-1")
    index = next(i for i, item in enumerate(results) if item.case_id == case.case_id)
    results[index] = lab.result_for(suite, run, case, 1, outcome=lab.Outcome.ALLOWED)
    report = lab.evaluate(suite, run, results, now=run.ended_at)
    assert not report.ready
    assert report.severe_attack_successes == 1
    assert report.attack_case_success_rate == 0.5
    assert report.attack_attempt_success_rate == 0.25
    assert report.family_attack_success_rates["privilege-abuse"] == 1.0


@pytest.mark.parametrize("keep_adversarial", [True, False])
def test_suite_requires_attack_and_valid_task_populations(lab, keep_adversarial: bool) -> None:
    suite, run, _ = fixture(lab)
    cases = tuple(case for case in suite.cases if case.adversarial is keep_adversarial)
    invalid_suite = replace(suite, cases=cases)
    invalid_run = replace(run, suite_digest=invalid_suite.digest)
    with pytest.raises(ValueError, match="adversarial and valid-task"):
        lab.evaluate(invalid_suite, invalid_run, [], now=invalid_run.ended_at)


def test_foreign_and_duplicate_results_are_rejected_before_metrics(lab) -> None:
    suite, run, results = fixture(lab)
    with pytest.raises(ValueError, match="undeclared"):
        lab.evaluate(suite, run, [*results, replace(results[0], case_id="foreign")], now=run.ended_at)
    with pytest.raises(ValueError, match="unique"):
        lab.evaluate(suite, run, [*results, results[0]], now=run.ended_at)


def test_stale_target_binding_is_excluded_and_blocks_coverage(lab) -> None:
    suite, run, results = fixture(lab)
    results[0] = replace(results[0], target_version="release-6")
    report = lab.evaluate(suite, run, results, now=run.ended_at)
    assert not report.ready
    assert any(item.startswith("binding-target:inj-1") for item in report.blockers)
    assert any(item.startswith("missing-attempts:inj-1") for item in report.blockers)
    assert report.case_coverage < 1 and report.execution_coverage < 1


@pytest.mark.parametrize("state,count_field", [("HARNESS_ERROR", "harness_error_count"), ("TARGET_ERROR", "target_error_count")])
def test_execution_errors_never_count_as_safe_blocks(lab, state: str, count_field: str) -> None:
    suite, run, results = fixture(lab)
    case = suite.cases[0]
    results[0] = lab.result_for(
        suite,
        run,
        case,
        1,
        execution_state=getattr(lab.ExecutionState, state),
    )
    report = lab.evaluate(suite, run, results, now=run.ended_at)
    assert not report.ready and getattr(report, count_field) == 1
    assert report.execution_coverage < 1
    assert report.attack_attempt_success_rate == 0


def test_trace_and_control_claims_require_bound_evidence(lab) -> None:
    suite, run, results = fixture(lab)
    results[0] = replace(results[0], trace_id="", evidence_ids=(), observed_control="model-claim")
    report = lab.evaluate(suite, run, results, now=run.ended_at)
    assert not report.ready
    assert any(item.startswith("untraceable:inj-1") for item in report.blockers)
    assert any(item.startswith("control-mismatch:inj-1") for item in report.blockers)
    assert report.trace_coverage < 1


def test_valid_task_blocking_uses_its_own_denominator(lab) -> None:
    suite, run, results = fixture(lab)
    case = next(item for item in suite.cases if not item.adversarial)
    index = next(i for i, item in enumerate(results) if item.case_id == case.case_id)
    results[index] = lab.result_for(suite, run, case, 1, outcome=lab.Outcome.BLOCKED)
    report = lab.evaluate(suite, run, results, now=run.ended_at)
    assert not report.ready and report.false_block_rate == 1.0
    assert report.attack_case_success_rate == 0


def test_tampered_manifest_and_invalid_threshold_fail_closed(lab) -> None:
    suite, run, results = fixture(lab)
    report = lab.evaluate(suite, replace(run, suite_digest="0" * 64), results, now=run.ended_at)
    assert not report.ready and "suite-digest-mismatch" in report.blockers
    with pytest.raises(ValueError, match="finite"):
        lab.evaluate(
            suite,
            run,
            results,
            policy=lab.EvaluationPolicy(maximum_false_block_rate=float("nan")),
            now=run.ended_at,
        )


def test_invalid_result_types_cannot_be_misread_as_completed(lab) -> None:
    suite, run, results = fixture(lab)
    malformed = replace(results[0], execution_state="completed", outcome=None)
    with pytest.raises(ValueError, match="ExecutionState"):
        lab.evaluate(suite, run, [malformed, *results[1:]], now=run.ended_at)


def test_promptfoo_provider_returns_bounded_host_evidence(lab, promptfoo) -> None:
    suite, run, _ = fixture(lab, attempts=1)
    case = suite.cases[0]
    response = promptfoo.call_api(
        json.dumps(
            {
                "case_id": case.case_id,
                "adversarial": case.adversarial,
                "expected_control": case.expected_control,
            }
        ),
        {},
        {},
    )
    result = promptfoo.result_from_output(
        response["output"],
        suite=suite,
        run=run,
        case=case,
        attempt_id="pf-1",
        observed_at=run.started_at,
    )
    assert result.outcome is lab.Outcome.BLOCKED
    assert result.trace_id and result.evidence_ids
    rendered = repr(response)
    assert "secret" not in rendered.lower() and "prompt" not in json.loads(response["output"])


def test_promptfoo_adapter_rejects_case_substitution(lab, promptfoo) -> None:
    suite, run, _ = fixture(lab, attempts=1)
    output = json.dumps(
        {
            "case_id": "scope-1",
            "outcome": "blocked",
            "observed_control": "action-policy",
            "trace_id": "trace-1",
            "evidence_ids": ["receipt-1"],
        }
    )
    with pytest.raises(ValueError, match="expected case"):
        promptfoo.result_from_output(
            output,
            suite=suite,
            run=run,
            case=suite.cases[0],
            attempt_id="pf-1",
            observed_at=run.started_at,
        )
