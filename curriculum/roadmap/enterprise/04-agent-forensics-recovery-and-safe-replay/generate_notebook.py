"""Generate the Enterprise 04 notebook deterministically."""
from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "forensic_recovery.ipynb"


def markdown(cell_id: str, source: str):
    cell = nbf.v4.new_markdown_cell(source.strip())
    cell["id"] = cell_id
    return cell


def code(cell_id: str, source: str):
    cell = nbf.v4.new_code_cell(source.strip())
    cell["id"] = cell_id
    return cell


def build_notebook():
    notebook = nbf.v4.new_notebook()
    notebook["metadata"] = {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        markdown("e04-title", """
# Enterprise 04 — Agent Forensics, Recovery, and Safe Replay

**Goal:** reconstruct trustworthy evidence, reconcile ambiguous effects, and
recover only through an exact, current, independently approved plan that reuses
the original logical operation identity.

This notebook is deterministic, credential-free, and makes no external calls.
It uses the real `cryptography` Ed25519 implementation.

![Forensic evidence admission, recovery planning, and safe replay](architecture.svg)
"""),
        markdown("e04-thesis", """
## Security thesis

Prior agent output and checkpoints are evidence, not authority. Trusted
application code authenticates evidence, exposes missing or altered history,
validates the checkpoint, reconciles provider state, authorizes and approves
the exact replay, executes with the original logical ID, verifies
postconditions, and owns the terminal state.
"""),
        code("e04-imports", """
from dataclasses import asdict, replace
import json

import fixtures
import forensics_recovery as fr
import lab

scenario = fixtures.build_scenario()
print({"case": scenario.case.case_id, "tenant": scenario.case.tenant,
       "events": len(scenario.store.events), "state": scenario.case.state.value})
"""),
        markdown("e04-signatures", """
## 1. Verify real Ed25519 evidence signatures

The fixed private seed is a public course fixture. The SDK call proves that the
canonical payload matches a signature under a configured public key; it does
not prove the event is true, complete, benign, or currently authorized.
"""),
        code("e04-signatures-run", """
event = scenario.store.events["event:checkpoint:42"]
verified = scenario.keyring.verify(event.key_id, fr.event_payload(event), event.signature)
public_key = scenario.keyring.public_key_hex(event.key_id)
print({"key_id": event.key_id, "public_key": public_key, "verified": verified})
assert verified
assert len(public_key) == 64
"""),
        markdown("e04-chain", """
## 2. Inspect the admitted per-source chain

Each event carries the next source sequence and previous canonical event
digest. Source order is stronger than sorting arbitrary device timestamps, but
it still does not create a global order across independent sources.
"""),
        code("e04-chain-run", """
chain = [
    {"sequence": event.source_sequence, "event": event.event_id,
     "previous": event.previous_source_digest[:12], "digest": fr.event_digest(event)[:12]}
    for event in sorted(scenario.store.events.values(), key=lambda item: item.source_sequence)
]
print(json.dumps(chain, indent=2))
assert chain[0]["previous"] == "GENESIS"
assert len(chain) == 5
"""),
        markdown("e04-chronology", """
## 3. Bind completeness and integrity into one chronology digest

The analyzer uses required event IDs and the signed source high-watermark. It
reverifies signatures and links rather than trusting admission-time success.
"""),
        code("e04-chronology-run", """
report = scenario.report
print(json.dumps(asdict(report), indent=2))
assert report.complete
assert not report.missing_required_event_ids
assert not report.sequence_gaps
assert not report.tampered_event_ids
"""),
        markdown("e04-tamper", """
## 4. Detect post-admission storage tampering

Changing an admitted payload digest without the signing key invalidates the
event and its successor link. Recovery must stop before planning.
"""),
        code("e04-tamper-run", """
tampered = fixtures.build_scenario()
event_id = "event:effect-result:42"
tampered.store.events[event_id] = fixtures.altered_event(
    tampered.store.events[event_id], payload_digest=fr.digest("forged-success"))
tamper_report = tampered.analyzer.analyze(
    case_id=tampered.checkpoint.case_id, tenant=tampered.checkpoint.tenant,
    required_event_ids=tampered.checkpoint.expected_event_ids,
    source_high_watermarks=tampered.checkpoint.source_high_watermarks)
print({"complete": tamper_report.complete,
       "tampered": tamper_report.tampered_event_ids})
assert not tamper_report.complete
assert event_id in tamper_report.tampered_event_ids
"""),
        markdown("e04-checkpoint", """
## 5. Validate the signed checkpoint manifest

The manifest binds tenant, case, state, code, old policy evidence, chronology,
verified containment, expected source heads, and exact pending effects. The old
policy version is evidence; the recovery plan uses current policy.
"""),
        code("e04-checkpoint-run", """
checkpoint = scenario.checkpoint
valid = scenario.keyring.verify(
    checkpoint.key_id, fr.checkpoint_payload(checkpoint), checkpoint.signature)
print({"checkpoint": checkpoint.checkpoint_id, "code": checkpoint.code_version,
       "captured_policy": checkpoint.captured_policy_version,
       "signature_valid": valid, "effects": len(checkpoint.effects)})
assert valid
assert checkpoint.chronology_digest == report.chronology_digest
"""),
        markdown("e04-plan", """
## 6. Reconcile every effect before replay

The case update already committed and must be skipped. The audit notification
has an authoritative absence and may be attempted under its original logical
operation ID. Planning does not dispatch anything.
"""),
        code("e04-plan-run", """
plan, approval = fixtures.approved_recovery(scenario)
decisions = [(item.intent.logical_operation_id, item.decision.value, item.reason)
             for item in plan.items]
print(json.dumps(decisions, indent=2))
assert [item.decision for item in plan.items] == [
    fr.ReplayDecision.SKIP_COMMITTED, fr.ReplayDecision.REPLAY_ALLOWED]
assert scenario.provider.effect_count == 0
"""),
        markdown("e04-conflicts", """
## 7. Keep conflicts and non-replayable work non-executable

Same logical ID with different intent is an identity collision. A
non-replayable operation remains manual even if a model recommends retrying.
"""),
        code("e04-conflicts-run", """
conflict = fixtures.build_scenario()
intent = conflict.checkpoint.effects[0]
conflict.provider.observations[intent.logical_operation_id] = fr.ProviderObservation(
    intent.logical_operation_id, "different-intent", fr.EffectStatus.COMMITTED, True)
conflict_plan, _ = fixtures.approved_recovery(conflict)

manual = fixtures.build_scenario()
manual_effects = (manual.checkpoint.effects[0],
                  replace(manual.checkpoint.effects[1], replayable=False))
manual.checkpoint = manual.keyring.sign_checkpoint(
    replace(manual.checkpoint, effects=manual_effects, signature=""),
    "checkpoint-authority-2026-11")
manual_plan, _ = fixtures.approved_recovery(manual)
print({"conflict": conflict_plan.items[0].decision.value,
       "manual": manual_plan.items[1].decision.value})
assert conflict_plan.items[0].decision is fr.ReplayDecision.DENIED
assert manual_plan.items[1].decision is fr.ReplayDecision.REVIEW_REQUIRED
"""),
        markdown("e04-approval", """
## 8. Bind and consume exact recovery authority

The signed approval covers the plan digest, current case version, tenant,
policy, approver, issue time, and expiry. A separate recovery subject must still
be authenticated and currently authorized.
"""),
        code("e04-approval-run", """
approval_valid = scenario.keyring.verify(
    approval.key_id, fr.approval_payload(approval), approval.signature)
print({"approval": approval.approval_id, "approver": approval.approved_by,
       "case_version": approval.expected_case_version,
       "plan_digest": approval.plan_digest[:16], "valid": approval_valid})
assert approval_valid
assert approval.plan_digest == plan.plan_digest
assert approval.expected_case_version == scenario.case.version
"""),
        markdown("e04-execute", """
## 9. Execute one bounded effect and verify both postconditions

The executor re-queries provider state, skips the existing commit, dispatches
the authorized absence with the original logical ID, and verifies the provider
ledger. One new attempt ID does not become a new business operation.
"""),
        code("e04-execute-run", """
result = scenario.executor.execute(
    scenario.case, plan, approval, scenario.responder, scenario.provider,
    scenario.authorizer, now=121)
print(json.dumps({"reason": result.reason, "state": result.state.value,
                  "receipts": [asdict(item) for item in result.receipts]},
                 indent=2, default=lambda value: value.value))
assert result.state is fr.RecoveryState.RECOVERED
assert scenario.provider.effect_count == 1
assert all(receipt.verified for receipt in result.receipts)
"""),
        markdown("e04-authorization", """
## 10. Recheck current authorization before consuming approval

Old policy and a valid signature cannot grant present authority. Removing the
audit permission denies recovery before approval consumption or dispatch.
"""),
        code("e04-authorization-run", """
unauthorized = fixtures.build_scenario()
unauthorized_plan, unauthorized_approval = fixtures.approved_recovery(unauthorized)
denied = unauthorized.executor.execute(
    unauthorized.case, unauthorized_plan, unauthorized_approval,
    unauthorized.responder, unauthorized.provider,
    fr.CurrentAuthorizer(frozenset()), now=121)
print({"accepted": denied.accepted, "reason": denied.reason,
       "approval_consumed": unauthorized_approval.approval_id in unauthorized.executor.used_approvals,
       "effects": unauthorized.provider.effect_count})
assert denied.reason == "current-authorization-denied"
assert unauthorized.provider.effect_count == 0
"""),
        markdown("e04-timeout", """
## 11. Preserve timeout-after-commit as unknown

The provider commits the audit notification and then times out. The first plan
ends `recovery-incomplete`. A new plan reconciles the same logical ID as
committed and skips it; no duplicate effect occurs.
"""),
        code("e04-timeout-run", """
timeout = fixtures.build_scenario()
logical_id = timeout.checkpoint.effects[1].logical_operation_id
timeout.provider.timeout_after_commit_ids.add(logical_id)
first_plan, first_approval = fixtures.approved_recovery(timeout)
first = timeout.executor.execute(
    timeout.case, first_plan, first_approval, timeout.responder,
    timeout.provider, timeout.authorizer, now=121)
count_after_timeout = timeout.provider.effect_count
timeout.provider.timeout_after_commit_ids.clear()
second_plan, second_approval = fixtures.approved_recovery(
    timeout, now=130, approval_id="approval:reconciled")
second = timeout.executor.execute(
    timeout.case, second_plan, second_approval, timeout.responder,
    timeout.provider, timeout.authorizer, now=131)
print({"first": first.state.value, "second": second.state.value,
       "effects_before": count_after_timeout, "effects_after": timeout.provider.effect_count,
       "new_decisions": [item.decision.value for item in second_plan.items]})
assert first.state is fr.RecoveryState.RECOVERY_INCOMPLETE
assert second.state is fr.RecoveryState.RECOVERED
assert timeout.provider.effect_count == count_after_timeout == 1
"""),
        markdown("e04-metrics", """
## 12. Evaluate valid, attack, boundary, and failure populations

The metrics keep safety, valid recovery, false blocks, tamper detection,
duplicate effects, and reconciliation separate. A high average cannot hide one
duplicated consequential effect.
"""),
        code("e04-metrics-run", """
evaluation = lab.evaluate_controls()
print(json.dumps(asdict(evaluation), indent=2))
assert (evaluation.valid_cases, evaluation.attack_cases,
        evaluation.boundary_cases, evaluation.failure_cases) == (2, 3, 2, 2)
assert evaluation.tamper_detection_rate == 1
assert evaluation.unsafe_replay_rate == 0
assert evaluation.duplicate_effect_count == 0
assert evaluation.valid_recovery_success_rate == 1
assert evaluation.false_block_rate == 0
assert evaluation.unknown_outcomes_reconciled_rate == 1
"""),
        markdown("e04-production", """
## Production upgrade and checkpoint

Replace fixture keys with HSM/KMS-backed custody and workload identity; memory
evidence with retention-locked storage and independent signed heads; integer
time with clock-health and trusted timestamp evidence; the synthetic provider
with documented query/idempotency contracts; the approval set with an atomic
durable transaction; and the static authorizer with current identity, resource,
purpose, environment, and risk policy.

**Checkpoint:** make the provider query unavailable for an old timeout, change
the current policy, and propose a new logical ID. The correct plan must remain
non-executable. Pass only when the original ambiguity is explicit, the new ID
cannot duplicate the effect, old policy grants nothing, approval cannot repair
the unsafe plan, and no model text changes the recovery state.
"""),
    ]
    return notebook


def main() -> None:
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")


if __name__ == "__main__":
    main()
