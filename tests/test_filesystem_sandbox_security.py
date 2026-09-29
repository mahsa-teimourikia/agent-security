"""Focused invariants for Intermediate 05 sandbox security."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "05-filesystem-code-execution-and-sandbox-security"
SPEC = importlib.util.spec_from_file_location("intermediate_05_sandbox_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def issue_safe(scenario, request_id: str = "test:issue"):
    return scenario.broker.issue(
        "attest:north",
        LAB.ExecutionRequest(request_id, "archive:north:safe", "program:safe"),
        now=LAB.NOW,
    )


def execute_safe(scenario, grant, request_id: str = "test:execute"):
    return scenario.runtime.execute(
        "attest:north", grant.grant_id, request_id=request_id, now=LAB.NOW
    )


def test_declared_evaluation_has_explicit_populations_and_semantics() -> None:
    report, observations = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (24, 4, 18, 2)
    assert (report.escape_cases, report.forbidden_read_cases, report.resource_limit_cases) == (6, 2, 5)
    assert report.valid_job_completion_rate == 1.0
    assert report.escape_success_rate == 0.0
    assert report.forbidden_read_success_rate == 0.0
    assert report.resource_limit_enforcement_rate == 1.0
    assert report.network_attempt_success_rate == 0.0
    assert report.replay_acceptance_rate == 0.0
    assert report.failure_error_preservation_rate == 1.0
    assert report.cleanup_completeness_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert report.unsafe_baseline_escape_rate == 1.0
    assert all(item.status == "error" for item in observations if item.kind is LAB.CaseKind.FAILURE)


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("../host", "path-traversal"),
        ("%2e%2e/host", "path-traversal"),
        ("%252e%252e/host", "path-traversal"),
        ("input/%2525252e%2525252e/secret", "path-encoding-depth"),
        ("..\\host", "path-traversal"),
        ("/etc/passwd", "path-absolute"),
        ("C:\\Windows\\system.ini", "path-absolute"),
        ("bad\x00name", "path-invalid"),
    ],
)
def test_canonicalization_rejects_direct_encoded_and_platform_escape_forms(
    path: str, reason: str
) -> None:
    assert LAB.canonical_relative_path(path) == (None, reason)


def test_archive_admission_rejects_links_collisions_and_expansion_bombs() -> None:
    scenario = LAB.build_scenario()
    fixtures = {
        "symlink": (
            LAB.ArchiveMember("data/link", LAB.MemberKind.SYMLINK, target="../../host"),
        ),
        "hardlink": (
            LAB.ArchiveMember("data/link", LAB.MemberKind.HARDLINK, target="host"),
        ),
        "special": (LAB.ArchiveMember("data/device", LAB.MemberKind.SPECIAL),),
        "collision": (
            LAB.ArchiveMember("DATA.csv", LAB.MemberKind.FILE, 1, 1),
            LAB.ArchiveMember("data.csv", LAB.MemberKind.FILE, 1, 1),
        ),
        "bomb": (
            LAB.ArchiveMember("data.csv", LAB.MemberKind.FILE, 100_001, 1),
        ),
    }
    expected = {
        "symlink": "archive-links-denied",
        "hardlink": "archive-links-denied",
        "special": "archive-special-file",
        "collision": "archive-path-collision",
        "bomb": "archive-compression-ratio",
    }
    for label, members in fixtures.items():
        archive = LAB.archive_fixture(f"archive:{label}", "north", members)
        assert scenario.inspector.inspect(archive)[1] == expected[label]


def test_valid_job_is_useful_destroyed_and_never_touches_host_or_network() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id="program:safe", request_id="test:valid", now=LAB.NOW,
    )
    assert response.status is LAB.DecisionStatus.ALLOW
    assert response.report and '"status": "complete"' in response.report
    assert scenario.runtime.host_read_count == 0
    assert scenario.runtime.host_write_count == 0
    assert scenario.runtime.network_dispatch_count == 0
    assert len(scenario.runtime.records) == 1
    assert all(record.destroyed for record in scenario.runtime.records.values())
    assert response.receipts[-1].sandbox_destroyed


def test_cross_tenant_archive_is_denied_before_sandbox_creation() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:south:safe",
        program_id="program:safe", request_id="test:tenant", now=LAB.NOW,
    )
    assert (response.status, response.reason) == (LAB.DecisionStatus.DENY, "archive-tenant")
    assert not scenario.runtime.records


@pytest.mark.parametrize(
    ("program_id", "reason"),
    [
        ("program:encoded-read", "sandbox-fs-path-traversal"),
        ("program:absolute-read", "sandbox-fs-path-absolute"),
        ("program:network", "sandbox-network-denied"),
        ("program:syscall", "sandbox-syscall-denied"),
        ("program:pids", "resource-pid-limit"),
        ("program:cpu", "resource-cpu-limit"),
        ("program:memory", "resource-memory-limit"),
        ("program:disk", "resource-disk-limit"),
        ("program:output", "resource-output-limit"),
    ],
)
def test_runtime_enforces_capability_and_resource_boundaries(
    program_id: str, reason: str
) -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id=program_id, request_id=f"test:{program_id}", now=LAB.NOW,
    )
    assert (response.status, response.reason, response.report) == (
        LAB.DecisionStatus.DENY, reason, None
    )
    assert scenario.runtime.host_read_count == 0
    assert scenario.runtime.host_write_count == 0
    assert scenario.runtime.network_dispatch_count == 0
    assert all(record.destroyed for record in scenario.runtime.records.values())


def test_stolen_grant_requires_named_workload_and_bound_key() -> None:
    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:sender").grant
    wrong_workload = scenario.runtime.execute(
        "attest:stolen", grant.grant_id, request_id="test:wrong-workload", now=LAB.NOW
    )
    assert wrong_workload.reason == "execution-sender"

    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:key").grant
    original = scenario.workloads.attestations["attest:north"]
    scenario.workloads.attestations["attest:north"] = replace(
        original, key_thumbprint="key:attacker"
    )
    wrong_key = execute_safe(scenario, grant, "test:wrong-key")
    assert wrong_key.reason == "execution-sender-key"


def test_expiry_revocation_policy_image_archive_program_and_integrity_are_current() -> None:
    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:expiry").grant
    assert scenario.broker.validate_current(
        grant, now=LAB.NOW + timedelta(seconds=45)
    )[1] == "execution-grant-expired"

    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:revoke").grant
    assert scenario.broker.revoke(grant.grant_id, "incident")
    assert scenario.broker.validate_current(grant, now=LAB.NOW)[1] == "execution-grant-revoked"

    for mutation, expected in (
        (lambda s: setattr(s.policy, "version", "sandbox-policy-v6"), "sandbox-policy-version-changed"),
        (lambda s: setattr(s.policy, "image_digest", "sha256:new-image"), "sandbox-image-changed"),
        (
            lambda s: s.archives.archives.__setitem__(
                "archive:north:safe",
                LAB.archive_fixture(
                    "archive:north:safe", "north",
                    (LAB.ArchiveMember("changed.txt", LAB.MemberKind.FILE, 1, 1),),
                ),
            ),
            "archive-version-changed",
        ),
        (
            lambda s: s.programs.programs.__setitem__(
                "program:safe",
                LAB.program_fixture(
                    "program:safe", (LAB.ProgramOperation(LAB.OperationKind.CPU, amount=1),)
                ),
            ),
            "program-version-changed",
        ),
    ):
        scenario = LAB.build_scenario()
        grant = issue_safe(scenario, f"test:{expected}").grant
        mutation(scenario)
        assert scenario.broker.validate_current(grant, now=LAB.NOW)[1] == expected

    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:integrity").grant
    tampered = replace(grant, tenant="south")
    scenario.broker.grants[grant.grant_id] = tampered
    assert scenario.broker.validate_current(tampered, now=LAB.NOW)[1] == "execution-grant-integrity"


def test_atomic_claim_allows_one_concurrent_execution() -> None:
    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:race").grant

    def invoke(index: int):
        return execute_safe(scenario, grant, f"test:race:{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(invoke, range(8)))
    assert sum(item.status is LAB.DecisionStatus.ALLOW for item in decisions) == 1
    assert sum(item.reason == "execution-grant-replayed" for item in decisions) == 7
    assert len(scenario.runtime.records) == 1
    assert all(record.destroyed for record in scenario.runtime.records.values())


def test_idempotency_rejects_request_id_collision() -> None:
    scenario = LAB.build_scenario()
    request = LAB.ExecutionRequest("test:idempotent", "archive:north:safe", "program:safe")
    first = scenario.broker.issue("attest:north", request, now=LAB.NOW)
    retry = scenario.broker.issue("attest:north", request, now=LAB.NOW)
    collision = scenario.broker.issue(
        "attest:north", replace(request, program_id="program:network"), now=LAB.NOW
    )
    assert retry.status is LAB.DecisionStatus.IDEMPOTENT
    assert retry.grant == first.grant
    assert (collision.status, collision.reason) == (
        LAB.DecisionStatus.DENY, "request-id-collision"
    )


def test_dependency_failures_are_errors_without_host_fallback() -> None:
    for dependency in ("workloads", "archives", "programs", "broker", "runtime"):
        scenario = LAB.build_scenario()
        if dependency == "runtime":
            issued = issue_safe(scenario, "test:runtime-failure")
            scenario.runtime.available = False
            decision = execute_safe(scenario, issued.grant, "test:runtime-failure:execute")
            assert decision.status is LAB.DecisionStatus.ERROR
        else:
            getattr(scenario, dependency).available = False
            response = scenario.application.analyze_archive(
                attestation_id="attest:north", archive_id="archive:north:safe",
                program_id="program:safe", request_id=f"test:failure:{dependency}", now=LAB.NOW,
            )
            assert response.status is LAB.DecisionStatus.ERROR
        assert scenario.application.fallback_execution_count == 0
        assert scenario.runtime.host_read_count == 0
        assert scenario.runtime.host_write_count == 0


def test_receipts_exclude_paths_program_operations_and_report_content() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.analyze_archive(
        attestation_id="attest:north", archive_id="archive:north:safe",
        program_id="program:safe", request_id="test:audit", now=LAB.NOW,
    )
    serialized = repr(scenario.audit.events)
    assert "orders.csv" not in serialized
    assert "report.json" not in serialized
    assert response.report not in serialized
    assert "169.254.169.254" not in serialized
