"""Focused tests for Foundation 07 context and evidence security."""
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "07-context-and-evidence-security"
SPEC = importlib.util.spec_from_file_location("foundation_07_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def compile_ids(key: str, *source_ids: str, budget: int = 4):
    registry = LAB.build_registry()
    request = LAB.request_for(key)
    refs = tuple(LAB.CandidateRef.exact(registry.records[item]) for item in source_ids)
    return registry, LAB.ContextCompiler(registry).compile(request, refs, now=LAB.NOW, max_context_units=budget)


def test_declared_evaluation_separates_safety_utility_and_failures() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (14, 4, 8, 2)
    assert report.valid_task_success_rate == report.attack_block_rate == 1.0
    assert report.attack_effect_rate == report.unauthorized_admission_rate == report.stale_admission_rate == 0.0
    assert report.conflict_surfacing_rate == report.citation_integrity_rate == report.trace_completeness_rate == 1.0
    assert report.baseline_attack_acceptance_rate == 1.0
    assert all(case.release.status is LAB.ReleaseStatus.ERROR for case in cases if case.kind is LAB.CaseKind.FAILURE)


def test_exact_binding_tenant_classification_and_supersession_precede_selection() -> None:
    registry = LAB.build_registry()
    current = registry.records["policy:retention"]
    candidates = (
        LAB.CandidateRef(current.source_id, current.version, "f" * 64),
        LAB.CandidateRef.exact(registry.records["case:south:9"]),
        LAB.CandidateRef.exact(registry.records["secret:fraud"]),
        LAB.CandidateRef.exact(registry.records["policy:retention-old"]),
    )
    manifest = LAB.ContextCompiler(registry).compile(LAB.request_for("retention_days"), candidates, now=LAB.NOW)
    assert manifest.status is LAB.CompilationStatus.INSUFFICIENT
    assert {item.reason for item in manifest.decisions} == {"source-binding", "tenant", "classification", "superseded"}
    assert not manifest.entries


def test_lower_authority_observation_cannot_override_policy() -> None:
    registry, manifest = compile_ids("retention_days", "observation:retention", "policy:retention")
    assert manifest.status is LAB.CompilationStatus.READY
    resolved = manifest.resolved_claims[0]
    assert resolved.value == "30"
    assert resolved.authority is LAB.Authority.POLICY
    decision = LAB.ReleaseVerifier(registry).verify(
        manifest,
        (LAB.DraftClaim("retention_days", "90", (registry.records["observation:retention"].reference,)),),
        now=LAB.NOW,
    )
    assert decision.status is LAB.ReleaseStatus.BLOCKED
    assert decision.reason == "claim-not-resolved"


def test_equal_authority_disagreement_is_conflict_not_latest_wins() -> None:
    registry, manifest = compile_ids("case_owner", "case:conflict-a", "case:conflict-b")
    assert manifest.status is LAB.CompilationStatus.CONFLICT
    assert manifest.conflict_claims == ("case_owner",)
    decision = LAB.ReleaseVerifier(registry).verify(manifest, (), now=LAB.NOW)
    assert decision.status is LAB.ReleaseStatus.ABSTAINED


def test_budget_exclusion_recomputes_sufficiency() -> None:
    registry = LAB.build_registry()
    costly = LAB.make_evidence(
        "policy:costly", 1, "north", LAB.SourceKind.POLICY, LAB.Classification.CONFIDENTIAL,
        LAB.Authority.POLICY, "policy://costly", (("retention_days", "30"),), "Thirty days.",
        LAB.NOW - timedelta(days=1), LAB.NOW + timedelta(days=1), cost_units=5,
    )
    registry.records[costly.source_id] = costly
    manifest = LAB.ContextCompiler(registry).compile(
        LAB.request_for("retention_days"), (LAB.CandidateRef.exact(costly),), now=LAB.NOW, max_context_units=4,
    )
    assert manifest.status is LAB.CompilationStatus.INSUFFICIENT
    assert manifest.missing_claims == ("retention_days",)
    assert manifest.decisions[0].reason == "budget-excluded"


def test_duplicate_candidate_cannot_consume_context_budget_twice() -> None:
    registry = LAB.build_registry()
    policy = registry.records["policy:retention"]
    reference = LAB.CandidateRef.exact(policy)
    manifest = LAB.ContextCompiler(registry).compile(
        LAB.request_for("retention_days"), (reference, reference), now=LAB.NOW, max_context_units=1,
    )
    assert manifest.status is LAB.CompilationStatus.READY
    assert len(manifest.entries) == 1
    assert [item.reason for item in manifest.decisions] == ["admitted", "duplicate-candidate"]


def test_release_rejects_fabricated_unadmitted_and_laundered_citations() -> None:
    registry, manifest = compile_ids("retention_days", "policy:retention", "case:42")
    verifier = LAB.ReleaseVerifier(registry)
    fabricated = verifier.verify(manifest, (LAB.DraftClaim("retention_days", "30", ("fake@1#bad",)),), now=LAB.NOW)
    laundered = verifier.verify(
        manifest,
        (LAB.DraftClaim("retention_days", "30", (registry.records["case:42"].reference,)),),
        now=LAB.NOW,
    )
    unadmitted = verifier.verify(
        manifest,
        (LAB.DraftClaim("retention_days", "30", (registry.records["case:unretrieved"].reference,)),),
        now=LAB.NOW,
    )
    assert fabricated.reason == unadmitted.reason == "citation-not-in-manifest"
    assert laundered.reason == "citation-does-not-support-claim"


def test_release_revalidates_registry_after_compilation() -> None:
    registry, manifest = compile_ids("retention_days", "policy:retention")
    record = registry.records["policy:retention"]
    registry.records[record.source_id] = replace(record, lifecycle=LAB.Lifecycle.REVOKED)
    decision = LAB.ReleaseVerifier(registry).verify(
        manifest, (LAB.DraftClaim("retention_days", "30", (record.reference,)),), now=LAB.NOW,
    )
    assert decision.status is LAB.ReleaseStatus.BLOCKED
    assert decision.reason == "citation-stale"


def test_registry_version_rotation_requires_recompilation() -> None:
    registry, manifest = compile_ids("retention_days", "policy:retention")
    record = registry.records["policy:retention"]
    registry.version = "registry-2"
    decision = LAB.ReleaseVerifier(registry).verify(
        manifest, (LAB.DraftClaim("retention_days", "30", (record.reference,)),), now=LAB.NOW,
    )
    assert decision.status is LAB.ReleaseStatus.BLOCKED
    assert decision.reason == "registry-version-changed"


def test_unauthenticated_request_is_denied_without_candidate_decisions() -> None:
    registry = LAB.build_registry()
    request = replace(LAB.request_for("retention_days"), authenticated=False)
    record = registry.records["policy:retention"]
    manifest = LAB.ContextCompiler(registry).compile(request, (LAB.CandidateRef.exact(record),), now=LAB.NOW)
    assert manifest.status is LAB.CompilationStatus.DENY
    assert not manifest.decisions and not manifest.entries


def test_trace_receipts_are_bounded_and_do_not_copy_source_text() -> None:
    _, manifest = compile_ids("retention_days", "policy:retention")
    receipt = {
        "trace_id": manifest.trace_id,
        "request_digest": manifest.request_digest,
        "manifest_digest": manifest.manifest_digest,
        "policy_version": manifest.policy_version,
        "registry_version": manifest.registry_version,
        "decisions": [(item.source_id, item.reason) for item in manifest.decisions],
    }
    assert "Approved case-artifact retention" not in repr(receipt)
    assert all(receipt[key] for key in ("trace_id", "request_digest", "manifest_digest", "policy_version", "registry_version"))
