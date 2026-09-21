"""Focused regressions for Foundation 02 threat-model assurance."""
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "02-threat-modeling-agentic-systems"
SPEC = importlib.util.spec_from_file_location("foundation_02_threat_modeling", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LAB
SPEC.loader.exec_module(LAB)


def test_architecture_is_versioned_and_every_flow_crosses_its_declared_boundary() -> None:
    architecture = LAB.build_architecture()
    assert architecture.version == LAB.ARCHITECTURE_VERSION
    assert architecture.required_flow_ids == {flow.flow_id for flow in architecture.flows}
    assert len(architecture.flows) == len(architecture.boundaries) == 7

    wrong = replace(architecture.flows[0], source_id="E4-model")
    with pytest.raises(ValueError, match="boundary route"):
        replace(architecture, flows=(wrong, *architecture.flows[1:]))


def test_model_suggestion_requires_authenticated_security_review() -> None:
    record = LAB.build_complete_model().records[2]
    proposal = LAB.ThreatProposal(
        **{field: getattr(record, field) for field in LAB.ThreatProposal.__dataclass_fields__}
    )
    untrusted = LAB.ReviewerContext("model:planner", frozenset({"security-reviewer"}), authenticated=False)
    wrong_role = LAB.ReviewerContext("user:7", frozenset({"developer"}))
    reviewer = LAB.ReviewerContext("reviewer:8", frozenset({"security-reviewer"}))
    assert LAB.admit_proposal(proposal, untrusted, residual_risk="reviewed").reason == "reviewer-unauthenticated"
    assert LAB.admit_proposal(proposal, wrong_role, residual_risk="reviewed").reason == "reviewer-role"
    admitted = LAB.admit_proposal(proposal, reviewer, residual_risk="accepted and monitored")
    assert admitted.accepted and admitted.record and admitted.record.reviewer_id == reviewer.subject


def test_complete_model_binds_threats_to_controls_tests_telemetry_and_owners() -> None:
    result = LAB.review_threat_model(LAB.build_complete_model())
    assert result.accepted and not result.blockers
    assert result.records == 7 and result.high_risk_records == 7
    assert result.required_flow_coverage == result.owner_coverage == 1
    assert result.high_risk_control_coverage == result.high_risk_test_coverage == 1
    assert result.high_risk_telemetry_coverage == 1


def test_row_count_baseline_misses_unverified_and_unknown_controls() -> None:
    model = LAB.build_complete_model()
    unsafe = replace(
        model,
        records=(replace(model.records[0], control_ids=("C404",), reviewer_id="model:planner"), *model.records[1:]),
    )
    assert LAB.unsafe_row_count_baseline(unsafe)
    review = LAB.review_threat_model(unsafe)
    assert not review.accepted
    assert "control-integrity:T1" in review.blockers
    assert "untrusted-reviewer:T1" in review.blockers


def test_architecture_drift_missing_tests_and_magic_risk_reduction_block_review() -> None:
    model = LAB.build_complete_model()
    primary = model.records[0]
    stale = LAB.review_threat_model(replace(model, architecture_version="old"))
    missing = LAB.review_threat_model(replace(model, records=model.records[:-1]))
    untested = LAB.review_threat_model(replace(model, records=(replace(primary, test_ids=()), *model.records[1:])))
    magic = LAB.review_threat_model(
        replace(model, records=(replace(primary, residual_likelihood=5, residual_impact=5), *model.records[1:]))
    )
    assert "stale-architecture-version" in stale.blockers
    assert "unmodeled-flow:F7-memory" in missing.blockers
    assert "test-integrity:T1" in untested.blockers
    assert "residual-exceeds-inherent:T1" in magic.blockers


def test_named_but_unexecuted_or_failed_test_evidence_does_not_verify_a_control() -> None:
    model = LAB.build_complete_model()
    unexecuted = replace(model.tests[0], executed=False, passed=False, evidence_id="")
    review = LAB.review_threat_model(replace(model, tests=(unexecuted, *model.tests[1:])))
    assert not review.accepted
    assert "control-not-verified:T1" in review.blockers
    assert review.high_risk_test_coverage < 1


def test_attack_tree_any_all_semantics_and_minimal_cut_sets() -> None:
    tree = LAB.build_exfiltration_tree()
    cuts = LAB.minimal_cut_sets(tree)
    assert cuts == {
        frozenset({"hostile-context-admitted", "proposal-treated-as-authority", "broad-egress"}),
        frozenset({"connector-compromised", "upstream-token-reused"}),
        frozenset({"memory-write-unchecked", "memory-read-unscoped"}),
    }
    assert all(LAB.attack_succeeds(tree, cut) for cut in cuts)
    assert not LAB.attack_succeeds(tree, frozenset({"hostile-context-admitted", "broad-egress"}))


def test_evaluation_populations_and_metric_directions_are_explicit() -> None:
    report, cases = LAB.evaluate_models()
    assert (report.cases, report.valid_cases, report.negative_cases) == (7, 1, 6)
    assert report.unexpected_acceptance_rate == 0
    assert report.valid_model_acceptance_rate == 1
    assert all(case.result.accepted == case.expected_valid for case in cases)
    assert report.required_flow_coverage == 1
    assert report.high_risk_control_coverage == report.high_risk_test_coverage == 1


def test_architecture_diagram_is_validated_and_deterministic() -> None:
    render_spec = importlib.util.spec_from_file_location("foundation_02_diagram", COURSE / "render_architecture.py")
    assert render_spec and render_spec.loader
    renderer = importlib.util.module_from_spec(render_spec)
    sys.modules[render_spec.name] = renderer
    render_spec.loader.exec_module(renderer)
    spec = json.loads((COURSE / "architecture-spec.json").read_text())
    renderer.validate(spec)
    assert renderer.render(spec) == (COURSE / "architecture.svg").read_text()
