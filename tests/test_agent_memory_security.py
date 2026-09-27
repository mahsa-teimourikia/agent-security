"""Focused tests for Intermediate 01 agent memory security."""
from dataclasses import replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "01-agent-memory-security"
SPEC = importlib.util.spec_from_file_location("intermediate_01_memory_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def test_declared_evaluation_separates_valid_attacks_and_failures() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (14, 4, 8, 2)
    assert report.valid_task_success_rate == report.trace_completeness_rate == 1.0
    assert report.attack_effect_rate == report.cross_scope_leakage_rate == 0.0
    assert report.stale_or_deleted_exposure_rate == 0.0
    assert report.baseline_attack_acceptance_rate == 1.0
    assert all(item.terminal_status == "error" for item in cases if item.kind is LAB.CaseKind.FAILURE)


def test_scope_and_source_authority_are_bound_before_persistence() -> None:
    service, sources = LAB.build_system()
    wrong_tenant = service.write(LAB.actor(), LAB.proposal(sources["south:email"]), now=LAB.NOW)
    summary = service.write(
        LAB.actor(request_id="request:summary"),
        LAB.proposal(sources["summary:email"], proposal_id="proposal:summary"),
        now=LAB.NOW,
    )
    assert (wrong_tenant.status, wrong_tenant.reason) == (LAB.WriteStatus.DENY, "source-scope")
    assert (summary.status, summary.reason) == (LAB.WriteStatus.DENY, "source-authority")
    assert not service.store.records


def test_consent_revocation_removes_semantic_memory_from_reads() -> None:
    service, sources = LAB.build_system()
    created = service.write(LAB.actor(), LAB.proposal(sources["confirm:email"]), now=LAB.NOW)
    assert created.status is LAB.WriteStatus.CREATED
    consent = service.consents.records["consent:personalization"]
    service.consents.records[consent.consent_id] = replace(consent, active=False)
    read = service.read(LAB.actor(request_id="request:read"), "preferred_contact_method", now=LAB.NOW)
    assert (read.status, read.reason, read.memory) == (LAB.ReadStatus.EMPTY, "consent-revoked", None)


def test_optimistic_versioning_prevents_lost_updates() -> None:
    service, sources = LAB.build_system()
    service.write(LAB.actor(), LAB.proposal(sources["confirm:email"]), now=LAB.NOW)
    stale = LAB.proposal(
        sources["confirm:sms"], proposal_id="proposal:stale-update", value="sms", expected_version=0,
    )
    decision = service.write(LAB.actor(request_id="request:update"), stale, now=LAB.NOW)
    assert (decision.status, decision.reason) == (LAB.WriteStatus.CONFLICT, "expected-version")
    assert service.store.current_record("north", "user-7", "preferred_contact_method").value == "email"


def test_exact_replay_is_idempotent_but_id_collision_is_denied() -> None:
    service, sources = LAB.build_system()
    item = LAB.proposal(sources["confirm:email"])
    first = service.write(LAB.actor(), item, now=LAB.NOW)
    replay = service.write(LAB.actor(), item, now=LAB.NOW)
    collision = service.write(
        LAB.actor(request_id="request:collision"),
        LAB.proposal(sources["confirm:sms"], proposal_id=item.proposal_id, value="sms", expected_version=1),
        now=LAB.NOW,
    )
    assert first.status is LAB.WriteStatus.CREATED
    assert replay.status is LAB.WriteStatus.IDEMPOTENT
    assert replay.record.memory_id == first.record.memory_id
    assert (collision.status, collision.reason) == (LAB.WriteStatus.DENY, "proposal-id-collision")


def test_subject_tombstone_blocks_late_retry_resurrection() -> None:
    service, sources = LAB.build_system()
    old_actor = LAB.actor()
    old_proposal = LAB.proposal(sources["confirm:email"])
    service.write(old_actor, old_proposal, now=LAB.NOW)
    deletion = service.delete_subject(
        LAB.actor(request_id="request:delete", purpose="privacy-delete"),
        now=LAB.NOW + timedelta(minutes=1),
    )
    retry = service.write(old_actor, replace(old_proposal, proposal_id="proposal:late"), now=LAB.NOW + timedelta(minutes=2))
    assert deletion.new_subject_epoch == 1
    assert (retry.status, retry.reason) == (LAB.WriteStatus.DENY, "subject-epoch")
    assert service.read(
        LAB.actor(request_id="request:new", epoch=1), "preferred_contact_method", now=LAB.NOW
    ).status is LAB.ReadStatus.EMPTY


def test_deletion_erases_superseded_values_and_new_epoch_uses_a_new_id() -> None:
    service, sources = LAB.build_system()
    first = service.write(LAB.actor(), LAB.proposal(sources["confirm:email"]), now=LAB.NOW)
    second = service.write(
        LAB.actor(request_id="request:update"),
        LAB.proposal(sources["confirm:sms"], proposal_id="proposal:update", value="sms", expected_version=1),
        now=LAB.NOW + timedelta(minutes=1),
    )
    deletion = service.delete_subject(
        LAB.actor(request_id="request:delete-all", purpose="privacy-delete"),
        now=LAB.NOW + timedelta(minutes=2),
    )
    replacement = service.write(
        LAB.actor(request_id="request:new-epoch", epoch=1),
        LAB.proposal(sources["confirm:email"], proposal_id="proposal:new-epoch", epoch=1),
        now=LAB.NOW + timedelta(minutes=3),
    )
    assert deletion.deleted_count == 2
    assert service.store.records[first.record.memory_id].value == ""
    assert service.store.records[second.record.memory_id].value == ""
    assert replacement.status is LAB.WriteStatus.CREATED
    assert replacement.record.memory_id not in {first.record.memory_id, second.record.memory_id}


def test_expired_record_is_not_returned_and_is_marked_expired() -> None:
    service, sources = LAB.build_system()
    created = service.write(
        LAB.actor(),
        LAB.proposal(sources["confirm:email"], ttl=timedelta(seconds=1)),
        now=LAB.NOW,
    )
    read = service.read(
        LAB.actor(request_id="request:expired"),
        "preferred_contact_method",
        now=LAB.NOW + timedelta(seconds=2),
    )
    assert (read.status, read.reason) == (LAB.ReadStatus.EMPTY, "expired")
    assert service.store.records[created.record.memory_id].lifecycle is LAB.Lifecycle.EXPIRED


def test_memory_view_is_data_and_never_grants_tool_authority() -> None:
    service, sources = LAB.build_system()
    service.write(LAB.actor(), LAB.proposal(sources["confirm:email"]), now=LAB.NOW)
    read = service.read(LAB.actor(request_id="request:view"), "preferred_contact_method", now=LAB.NOW)
    assert read.memory.untrusted_data is True
    assert read.memory.grants_authority is False


def test_registry_outage_is_error_not_an_empty_memory_result() -> None:
    service, sources = LAB.build_system()
    service.write(LAB.actor(), LAB.proposal(sources["confirm:email"]), now=LAB.NOW)
    service.consents.available = False
    read = service.read(LAB.actor(request_id="request:outage"), "preferred_contact_method", now=LAB.NOW)
    assert (read.status, read.reason) == (LAB.ReadStatus.ERROR, "registry-unavailable")


def test_receipts_are_bounded_and_do_not_copy_memory_values() -> None:
    service, sources = LAB.build_system()
    decision = service.write(LAB.actor(), LAB.proposal(sources["confirm:email"]), now=LAB.NOW)
    receipt = decision.receipt
    assert "email" not in repr(receipt)
    assert "user-7" not in repr(receipt)
    assert all((receipt.tenant_digest, receipt.subject_digest, receipt.proposal_digest, receipt.policy_version))
