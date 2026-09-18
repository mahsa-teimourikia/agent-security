"""Credential-free Promptfoo provider and result adapter for Advanced 01.

This is a deterministic harness integration, not a model-quality benchmark.
Production providers should expose host-verified tool, policy, and side-effect
evidence instead of asking a target model whether it behaved safely.
"""

from __future__ import annotations

from datetime import datetime
from importlib import import_module
import json
from typing import Any


core = import_module("01_attack_evaluation")


def _bounded_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{name} must be a non-empty string of at most 128 characters")
    return value


def call_api(prompt: str, options: dict[str, object], context: dict[str, object]) -> dict[str, object]:
    """Implement Promptfoo's Python-provider contract with synthetic evidence."""
    del options, context
    try:
        scenario = json.loads(prompt)
        if not isinstance(scenario, dict):
            raise ValueError("scenario must be a JSON object")
        case_id = _bounded_string(scenario.get("case_id"), "case_id")
        expected_control = _bounded_string(scenario.get("expected_control"), "expected_control")
        adversarial = scenario.get("adversarial")
        if not isinstance(adversarial, bool):
            raise ValueError("adversarial must be boolean")
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return {"error": f"invalid synthetic scenario: {exc}"}

    outcome = "blocked" if adversarial else "allowed"
    receipt = {
        "case_id": case_id,
        "outcome": outcome,
        "observed_control": expected_control,
        "trace_id": f"promptfoo-trace-{case_id}",
        "evidence_ids": [f"promptfoo-receipt-{case_id}"],
    }
    return {
        "output": json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        "cached": False,
        "latencyMs": 1,
        "metadata": {"fixture": "synthetic", "verifier": "host-owned"},
    }


def result_from_output(
    output: str,
    *,
    suite: core.EvaluationSuite,
    run: core.EvaluationRun,
    case: core.AttackCase,
    attempt_id: str,
    observed_at: datetime,
) -> core.CaseResult:
    """Admit the bounded fields that a production sidecar verifier would own."""
    payload = json.loads(output)
    if not isinstance(payload, dict):
        raise ValueError("Promptfoo output must be a JSON object")
    if payload.get("case_id") != case.case_id:
        raise ValueError("Promptfoo output is not bound to the expected case")
    observed_control = _bounded_string(payload.get("observed_control"), "observed_control")
    trace_id = _bounded_string(payload.get("trace_id"), "trace_id")
    raw_evidence = payload.get("evidence_ids")
    if not isinstance(raw_evidence, list) or not 1 <= len(raw_evidence) <= 8:
        raise ValueError("evidence_ids must be a bounded non-empty list")
    evidence_ids = tuple(_bounded_string(value, "evidence_id") for value in raw_evidence)
    try:
        outcome = core.Outcome(payload.get("outcome"))
    except ValueError as exc:
        raise ValueError("Promptfoo output has an unsupported outcome") from exc
    return core.CaseResult(
        run.run_id,
        case.case_id,
        _bounded_string(attempt_id, "attempt_id"),
        suite.version,
        suite.target_version,
        suite.policy_version,
        suite.environment,
        core.ExecutionState.COMPLETED,
        outcome,
        observed_control,
        trace_id,
        evidence_ids,
        observed_at,
        1,
    )


def demo() -> core.CaseResult:
    now = datetime.fromisoformat("2026-09-18T12:00:00+00:00")
    suite, run = core.build_suite(now=now, attempts=1)
    case = suite.cases[0]
    prompt = json.dumps(
        {
            "case_id": case.case_id,
            "adversarial": case.adversarial,
            "expected_control": case.expected_control,
        }
    )
    response = call_api(prompt, {}, {})
    result = result_from_output(
        str(response["output"]),
        suite=suite,
        run=run,
        case=case,
        attempt_id="promptfoo-attempt-1",
        observed_at=run.started_at,
    )
    assert result.outcome is core.Outcome.BLOCKED
    return result


if __name__ == "__main__":
    print(demo())
