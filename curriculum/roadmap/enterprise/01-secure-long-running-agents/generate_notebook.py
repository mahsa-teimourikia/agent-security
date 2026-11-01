"""Generate the Enterprise 01 notebook deterministically."""
from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "secure_long_running_agents.ipynb"


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
        markdown("e01-title", """
# Enterprise 01 — Secure Long-Running Agents

**Goal:** resume durable agent state only under fresh, bounded authority; keep
one owner; detect orphans; and reconcile ambiguous effects before retry.

This notebook is deterministic, credential-free, and causes no external side
effects. The final section uses the real OpenAI Agents SDK without a model call.

![Secure long-running-agent authority and effect lifecycle](architecture.svg)
"""),
        markdown("e01-thesis", """
## Security thesis

A checkpoint proves stored-state integrity, not present authority. The trusted
application revalidates identity, tenant, intent, policy, credentials, budget,
approval, workflow version, and the exact pending effect before issuing a short
lease. A workflow engine provides durability; it does not decide business
authority.
"""),
        code("e01-imports", """
from dataclasses import asdict, replace
from datetime import timedelta
import json

import secure_long_running_agents as lab

plane, actor, effect = lab.build_system()
checkpoint = plane.runs["run:north:42"].checkpoint
print({"phase": checkpoint.phase.value, "old_policy": checkpoint.policy_version,
       "signature_valid": plane.signer.verify(checkpoint)})
"""),
        markdown("e01-integrity", """
## 1. Integrity and authority are separate

The checkpoint is valid and intentionally contains old security versions. Remove
the current subject from the authority service: integrity remains true, but
resume must fail.
"""),
        code("e01-revocation", """
revoked_plane, revoked_actor, _ = lab.build_system()
revoked_plane.authority.allowed_subjects.clear()
denied = revoked_plane.resume(revoked_actor, "run:north:42",
    resume_request_id="notebook:revoked", expected_version=1, now=lab.NOW)
print({"checkpoint_valid": revoked_plane.signer.verify(revoked_plane.runs["run:north:42"].checkpoint),
       "resume": denied.decision.value, "reason": denied.reason})
assert denied.reason == "subject-revoked"
"""),
        markdown("e01-resume", """
## 2. Issue a fresh version-bound lease

The valid principal receives a lease bound to current policy, credential,
budget epoch, intent, state, and exact effect. Old checkpoint values are not
copied into the authority decision.
"""),
        code("e01-lease", """
resumed = plane.resume(actor, "run:north:42",
    resume_request_id="notebook:valid", expected_version=1, now=lab.NOW)
lease = resumed.lease
print(json.dumps({"decision": resumed.decision.value,
    "checkpoint_policy": checkpoint.policy_version,
    "lease_policy": lease.policy_version,
    "credential": lease.credential_version,
    "budget_epoch": lease.budget_epoch,
    "effect_digest": lease.effect_digest[:16]}, indent=2))
assert lease.policy_version == plane.authority.policy_version != checkpoint.policy_version
"""),
        markdown("e01-race", """
## 3. Enforce one resume owner

Two workers use the same expected record version. The application lock is a
teaching analogue for a transaction or compare-and-set. Exactly one wins.
"""),
        code("e01-race-run", """
race = lab.concurrent_resume_demo()
print([decision.value for decision in race])
assert race.count(lab.Decision.ALLOW) == 1
"""),
        markdown("e01-idempotency", """
## 4. Distinguish redelivery from a second owner

A duplicated stable resume request returns the existing lease. A new request
while the owner remains active conflicts. Queue delivery IDs should not replace
the caller's stable operation ID.
"""),
        code("e01-idempotency-run", """
idem_plane, idem_actor, _ = lab.build_system()
first = idem_plane.resume(idem_actor, "run:north:42",
    resume_request_id="stable:resume:42", expected_version=1, now=lab.NOW)
replay = idem_plane.resume(idem_actor, "run:north:42",
    resume_request_id="stable:resume:42", expected_version=1, now=lab.NOW)
competitor = idem_plane.resume(idem_actor, "run:north:42",
    resume_request_id="other:resume:42", expected_version=2, now=lab.NOW)
print({"redelivery": replay.decision.value, "competitor": competitor.decision.value})
assert replay.lease == first.lease
assert competitor.decision is lab.Decision.CONFLICT
"""),
        markdown("e01-heartbeat", """
## 5. Heartbeats renew liveness, not authority

A heartbeat moves the liveness deadline while the authority expiry stays fixed.
At the exact heartbeat deadline, an effect is stale and the orphan sweep may
release the owner.
"""),
        code("e01-heartbeat-run", """
hb_plane, hb_actor, hb_effect = lab.build_system()
hb_lease = hb_plane.resume(hb_actor, "run:north:42",
    resume_request_id="heartbeat:resume", expected_version=1, now=lab.NOW).lease
beat = hb_plane.heartbeat(hb_actor, "run:north:42", hb_lease.lease_id,
    now=lab.NOW + timedelta(minutes=1))
print({"old_deadline": hb_lease.heartbeat_deadline.isoformat(),
       "new_deadline": beat.lease.heartbeat_deadline.isoformat(),
       "authority_expiry_unchanged": beat.lease.expires_at == hb_lease.expires_at})
assert beat.lease.expires_at == hb_lease.expires_at
"""),
        markdown("e01-stale", """
## 6. Reject a lease after policy changes

Resume-time authorization is not enough for a consequential effect. The
executor checks current policy, credential, intent, budget epoch, liveness, and
exact effect again.
"""),
        code("e01-stale-run", """
stale_plane, stale_actor, stale_effect = lab.build_system()
stale_lease = stale_plane.resume(stale_actor, "run:north:42",
    resume_request_id="stale:resume", expected_version=1, now=lab.NOW).lease
stale_plane.authority.policy_version = "policy-emergency"
stale = stale_plane.execute(stale_actor, "run:north:42", stale_lease.lease_id,
    stale_effect, attempt_id="attempt:stale", provider=lab.SyntheticProvider(), now=lab.NOW)
print({"decision": stale.decision.value, "reason": stale.reason})
assert stale.reason == "policy-changed"
"""),
        markdown("e01-unknown", """
## 7. Reconcile unknown provider outcome before retry

The provider commits, but the response is lost. A second dispatch is denied.
Reconciliation queries the provider's authoritative record and completes the
original logical operation without a duplicate effect.
"""),
        code("e01-unknown-run", """
fx_plane, fx_actor, fx_effect = lab.build_system()
fx_lease = fx_plane.resume(fx_actor, "run:north:42",
    resume_request_id="effect:resume", expected_version=1, now=lab.NOW).lease
provider = lab.SyntheticProvider()
unknown = fx_plane.execute(fx_actor, "run:north:42", fx_lease.lease_id, fx_effect,
    attempt_id="attempt:1", provider=provider, now=lab.NOW, timeout_after_commit=True)
retry = fx_plane.execute(fx_actor, "run:north:42", fx_lease.lease_id, fx_effect,
    attempt_id="attempt:2", provider=provider, now=lab.NOW)
reconciled = fx_plane.reconcile(fx_actor, "run:north:42",
    fx_effect.logical_operation_id, provider, now=lab.NOW)
print({"first": unknown.decision.value, "retry": retry.reason,
       "reconcile": reconciled.reason, "provider_dispatches": provider.dispatches})
assert retry.reason == "reconcile-before-retry"
assert reconciled.reason == "committed-effect-reconciled"
assert provider.dispatches == 1
"""),
        markdown("e01-metrics", """
## 8. Evaluate declared populations with exact denominators

Valid, attack, boundary, and failure cases answer different questions. An
`UNKNOWN` outcome is never counted as a safe resume or successful valid run.
"""),
        code("e01-metrics-run", """
report = lab.evaluate_controls()
print(json.dumps(asdict(report), indent=2))
assert (report.valid_cases, report.attack_cases, report.boundary_cases, report.failure_cases) == (1, 4, 1, 2)
assert report.valid_completion_rate == report.orphan_detection_rate == report.safe_failure_rate == 1
assert report.unsafe_resume_rate == report.stale_lease_use_rate == report.duplicate_effect_rate == 0
"""),
        markdown("e01-sdk", """
## 9. Put real SDK state behind the same gate

The OpenAI Agents SDK bridge serializes a real `RunState`, stores it in a
digest-bound server-side vault, obtains a fresh application lease, and only then
deserializes it. Session continuity is not current enterprise authority.
"""),
        code("e01-sdk-run", """
import sdk_adapter

proof = await sdk_adapter.run_demo_async()
print(json.dumps(proof, indent=2))
assert proof["resume_decision"] == "allow"
assert proof["state_restored_after_gate"]
assert proof["tampered_state_rejected"]
assert not proof["contains_credentials"]
"""),
        markdown("e01-production", """
## Production upgrade

| Teaching boundary | Production replacement |
| --- | --- |
| dictionary + process lock | transactional multi-tenant store or workflow single-writer primitive |
| HMAC course key | KMS/HSM-backed authenticated encryption or signing with rotation |
| local principal | verified workforce/workload identity and tenant claims |
| local lease | durable lease with fencing token and regional failure policy |
| synthetic heartbeat | authenticated worker liveness evidence |
| synthetic provider | documented idempotency and authoritative outcome lookup |
| fixed cases | replay corpus, incidents, race tests, migration tests, and chaos |

Temporal, Dapr Workflow, Azure Durable Task, LangGraph, Restate, and the OpenAI
Agents SDK supply different persistence and orchestration primitives. The
application must still own current authorization and effect verification.
"""),
        markdown("e01-checkpoint", """
## Checkpoint

**Does a valid checkpoint digest prove that its old authorization is still
current?**

No. Integrity and current authority are separate checks. Revalidate identity,
tenant, intent, policy, credential, approval, budget, workflow compatibility,
time, and exact effect; then issue one short, version-bound lease.
"""),
    ]
    return notebook


def main() -> None:
    notebook = build_notebook()
    nbf.write(notebook, OUTPUT)
    print(f"generated {OUTPUT.name} with {len(notebook['cells'])} cells")


if __name__ == "__main__":
    main()
