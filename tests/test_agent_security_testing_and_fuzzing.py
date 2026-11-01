"""Invariant and evaluation tests for Advanced 07."""
from __future__ import annotations

from dataclasses import replace
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "advanced" / "07-agent-security-testing-and-fuzzing"
SPEC = importlib.util.spec_from_file_location("advanced_07_fuzzing_lab", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAB
SPEC.loader.exec_module(LAB)


def test_corpus_has_explicit_populations() -> None:
    corpus = LAB.build_corpus()
    counts = {kind: sum(case.kind is kind for case in corpus) for kind in LAB.CaseKind}
    assert counts == {
        LAB.CaseKind.VALID: 5,
        LAB.CaseKind.ATTACK: 14,
        LAB.CaseKind.BOUNDARY: 4,
        LAB.CaseKind.FAILURE: 3,
    }


@pytest.mark.parametrize("case", LAB.build_corpus(), ids=lambda item: item.case_id)
def test_secure_gateway_matches_labelled_case_expectation(case) -> None:
    result = LAB.run_case(case, LAB.SecureGateway)
    assert result.receipt.status is case.expected_status
    assert not result.findings


@pytest.mark.parametrize(
    "case_id",
    [
        "attack-cross-tenant-resource",
        "attack-claimed-tenant",
        "attack-fullwidth-command",
        "attack-casefold-command",
        "attack-missing-operation",
        "attack-stale-version",
        "attack-illegal-submit",
        "attack-execute-from-review",
        "attack-missing-approval",
        "attack-altered-after-approval",
        "attack-wrong-tenant-approval",
        "attack-stale-policy-approval",
        "attack-expired-approval",
        "attack-operation-collision",
    ],
)
def test_each_attack_is_contained_without_an_effect(case_id: str) -> None:
    case = next(item for item in LAB.build_corpus() if item.case_id == case_id)
    result = LAB.run_case(case)
    assert result.receipt.status is LAB.DecisionStatus.DENY
    assert not result.receipt.effect_applied


def test_secure_evaluation_uses_attack_denominator() -> None:
    report, _ = LAB.evaluate(LAB.SecureGateway)
    assert report.attack_cases == 14
    assert report.forbidden_outcomes == 0
    assert report.invariant_violation_rate == 0 / 14
    assert report.contained_attack_rate == 14 / 14


def test_valid_case_rejection_uses_only_valid_population() -> None:
    report, _ = LAB.evaluate(LAB.SecureGateway)
    assert report.valid_cases == 5
    assert report.valid_case_rejections == 0
    assert report.valid_case_rejection_rate == 0 / 5


def test_dependency_failures_are_errors_not_defenses() -> None:
    report, results = LAB.evaluate(LAB.SecureGateway)
    failures = [item for item in results if item.kind is LAB.CaseKind.FAILURE]
    assert report.explicit_dependency_errors == 3
    assert all(item.receipt.status is LAB.DecisionStatus.ERROR for item in failures)
    assert all(not item.receipt.effect_applied for item in failures)


def test_unsafe_baseline_produces_real_forbidden_outcomes() -> None:
    report, results = LAB.evaluate(LAB.UnsafeGateway)
    assert report.forbidden_outcomes == 5
    assert report.invariant_violation_rate == 5 / 14
    assert report.fail_open_dependency_outcomes == 3
    assert report.unique_failure_families == 7
    assert any(item.receipt.effect_applied for item in results if item.forbidden_outcome)


def test_oracle_does_not_count_a_blocked_attempt_as_violation() -> None:
    case = next(item for item in LAB.build_corpus() if item.case_id == "attack-fullwidth-command")
    result = LAB.run_case(case, LAB.SecureGateway)
    assert result.receipt.status is LAB.DecisionStatus.DENY
    assert not result.forbidden_outcome


def test_oracle_detects_parser_differential_effect() -> None:
    case = next(item for item in LAB.build_corpus() if item.case_id == "attack-fullwidth-command")
    result = LAB.run_case(case, LAB.UnsafeGateway)
    assert result.receipt.effect_applied
    assert {finding.invariant for finding in result.findings} >= {LAB.Invariant.EXACT_APPROVAL}


def test_claimed_identity_never_changes_secure_authority() -> None:
    actor = LAB.principals()["outsider"]
    base = LAB.request(
        LAB.Command.EXECUTE_EXPORT,
        "identity:1",
        state_version=2,
        approval_id="approval:identity",
    )
    cases = [
        LAB.FuzzCase("blank", LAB.CaseKind.ATTACK, actor, base, LAB.WorkflowState.APPROVED, 2, LAB.DecisionStatus.DENY),
        LAB.FuzzCase("claimed", LAB.CaseKind.ATTACK, actor, replace(base, claimed_tenant="north", claimed_subject="admin"), LAB.WorkflowState.APPROVED, 2, LAB.DecisionStatus.DENY),
    ]
    results = [LAB.run_case(case) for case in cases]
    assert [item.receipt.reason for item in results] == ["tenant-mismatch", "tenant-mismatch"]


def test_exact_approval_is_bound_to_destination() -> None:
    actor = LAB.principals()["requester"]
    original = LAB.request(
        LAB.Command.EXECUTE_EXPORT,
        "approval:destination",
        state_version=2,
        approval_id="approval:destination",
    )
    case = LAB.FuzzCase(
        "approval-binding",
        LAB.CaseKind.ATTACK,
        actor,
        original,
        LAB.WorkflowState.APPROVED,
        2,
        LAB.DecisionStatus.DENY,
        issue_approval=True,
    )
    gateway, workflow, _ = LAB.build_gateway(LAB.SecureGateway, case)
    altered = replace(original, destination="alternate.northstar.example")
    receipt = gateway.execute(actor, altered, step=1)
    assert receipt.reason == "approval-proposal-binding"
    assert not workflow.effects


def test_approval_is_consumed_once() -> None:
    case = next(item for item in LAB.build_corpus() if item.case_id == "valid-execute")
    gateway, workflow, _ = LAB.build_gateway(LAB.SecureGateway, case)
    first = gateway.execute(case.actor, case.request, step=1)
    workflow.state = LAB.WorkflowState.APPROVED
    workflow.version = 2
    gateway.operations.clear()
    second = gateway.execute(case.actor, replace(case.request, logical_operation_id="valid:execute:2"), step=2)
    assert first.effect_applied
    assert second.reason in {"approval-proposal-binding", "approval-replayed"}
    assert len(workflow.effects) == 1


def test_same_operation_with_changed_payload_is_collision() -> None:
    actor = LAB.principals()["requester"]
    workflow = LAB.Workflow("workflow:north:7", "north", "case:north:7")
    gateway = LAB.SecureGateway(workflow, LAB.resources())
    first = LAB.request(LAB.Command.SUBMIT_REVIEW, "operation:stable")
    assert gateway.execute(actor, first).status is LAB.DecisionStatus.ALLOW
    workflow.state = LAB.WorkflowState.DRAFT
    workflow.version = 0
    changed = replace(first, destination="changed.northstar.example")
    receipt = gateway.execute(actor, changed)
    assert receipt.reason == "operation-id-collision"


def test_same_operation_and_payload_is_idempotent_replay() -> None:
    actor = LAB.principals()["requester"]
    workflow = LAB.Workflow("workflow:north:7", "north", "case:north:7")
    gateway = LAB.SecureGateway(workflow, LAB.resources())
    item = LAB.request(LAB.Command.SUBMIT_REVIEW, "operation:stable")
    gateway.execute(actor, item)
    receipt = gateway.execute(actor, item)
    assert receipt.reason == "idempotent-replay"


def test_optimistic_lock_allows_only_one_racer() -> None:
    first, second = LAB.race_scenario()
    assert first.status is LAB.DecisionStatus.ALLOW
    assert second.status is LAB.DecisionStatus.DENY
    assert second.reason == "workflow-version-stale"


def test_encoded_sequence_minimizes_to_three_causal_steps() -> None:
    original = LAB.encoded_bypass_sequence()
    minimized = LAB.minimize_sequence(original, LAB.sequence_has_unsafe_forbidden_outcome)
    assert len(original) == 4
    assert [item.command for item in minimized] == [
        LAB.Command.SUBMIT_REVIEW.value,
        LAB.Command.APPROVE_EXPORT.value,
        "ｅxecute_export",
    ]


def test_minimized_sequence_reproduces_same_security_failure() -> None:
    minimized = LAB.minimize_sequence(
        LAB.encoded_bypass_sequence(),
        LAB.sequence_has_unsafe_forbidden_outcome,
    )
    assert LAB.sequence_has_unsafe_forbidden_outcome(minimized)
    assert not LAB.sequence_has_unsafe_forbidden_outcome(minimized[:-1])


def test_receipts_are_content_free_and_observable() -> None:
    case = next(item for item in LAB.build_corpus() if item.case_id == "valid-read")
    result = LAB.run_case(case)
    receipt = result.receipt
    assert receipt.audit_id.startswith("audit:")
    assert receipt.policy_version == LAB.POLICY_VERSION
    assert not hasattr(receipt, "payload")
    assert not hasattr(receipt, "chain_of_thought")


def test_report_is_reproducible() -> None:
    first, first_results = LAB.evaluate()
    second, second_results = LAB.evaluate()
    assert first == second
    assert [item.receipt.reason for item in first_results] == [item.receipt.reason for item in second_results]
    assert first.reproducibility_rate == 1.0


def test_demo_exposes_baseline_comparison_and_shrink() -> None:
    result = LAB.demo()
    assert result["secure"]["forbidden_outcomes"] == 0
    assert result["unsafe"]["forbidden_outcomes"] == 5
    assert result["unsafe"]["fail_open_dependency_outcomes"] == 3
    assert result["sequence_steps_before"] > result["sequence_steps_after"]
    assert result["race_statuses"] == ["allow", "deny"]
