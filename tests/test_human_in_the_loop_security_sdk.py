"""Real OpenAI Agents SDK interruption tests for Intermediate 10."""

import asyncio
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "10-human-in-the-loop-security"
SPEC = importlib.util.spec_from_file_location("intermediate_10_hitl_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def run() -> dict[str, object]:
    return asyncio.run(SDK.run_sdk_demo())


def test_real_sdk_interrupts_and_round_trips_pending_call() -> None:
    proof = run()
    assert proof["tool_name"] == "issue_refund"
    assert proof["call_id"] == "call-refund-42"
    assert proof["snapshot_contains_pending_call"]
    assert proof["snapshot_contains_arguments"]
    assert proof["server_snapshot_required"]


def test_sdk_schema_exposes_no_identity_or_approval_authority() -> None:
    proof = run()
    assert proof["strict_schema"]
    assert proof["schema_properties"] == [
        "amount_cents",
        "currency",
        "logical_operation_id",
        "reason",
        "resource_id",
    ]
    assert not ({"subject", "tenant", "roles", "approval_id", "approved"} & set(proof["schema_properties"]))


def test_sdk_pause_does_not_bypass_course_execution_boundary() -> None:
    proof = run()
    assert proof["course_review_status"] == "review-approved"
    assert proof["course_outcome"] == "effect-completed"
    assert proof["effect_applied"]
    assert proof["sdk_tool_executions"] == ()
    assert proof["receipt_phases"] == (
        "submission",
        "review",
        "execution",
        "outcome",
    )
