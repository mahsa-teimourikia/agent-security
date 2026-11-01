"""Generate the Enterprise 02 notebook deterministically."""
from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "kill_switches.ipynb"


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
        markdown("e02-title", """
# Enterprise 02 — Kill Switches, Revocation, and Safe Degradation

**Goal:** activate an independently operated, monotonically versioned kill
switch; enforce it at scheduling and effect boundaries; retain governed
diagnostics; reconcile in-flight work; and recover only under new authority.

This notebook is deterministic, credential-free, and causes no external side
effects. It uses the real OpenFeature Python SDK with an in-memory provider.

![Kill-switch distribution, enforcement, reconciliation, and recovery](architecture.svg)
"""),
        markdown("e02-thesis", """
## Security thesis

A model instruction cannot be the kill switch because it fails when the model
or context is compromised. Orchestration cancellation is useful but does not
revoke credentials, block detached effects, or undo commits. The trusted
application accepts authenticated incident commands, distributes a monotonic
control epoch, and checks current authority again at the effect boundary.
"""),
        code("e02-imports", """
from dataclasses import asdict, replace
import json

import kill_switches as ks

plane, operator, principal, gateway = ks.build_system()
print({"epoch": plane.snapshot.epoch, "mode": plane.snapshot.mode.value,
       "gateway_observed": gateway.observed_at})
"""),
        markdown("e02-command", """
## 1. Activate a signed, tenant-bound containment command

The operator moves the agent to read-only mode, revokes several capability
classes, and independently blocks the suspected destination. Epoch 1 must be
exactly the current epoch plus one.
"""),
        code("e02-command-run", """
command = ks.signed_command(
    plane, command_id="notebook:contain", epoch=1, mode=ks.Mode.READ_ONLY,
    revoke=frozenset({ks.Capability.WRITE, ks.Capability.TOOL,
                      ks.Capability.CREDENTIAL, ks.Capability.MCP,
                      ks.Capability.EGRESS}),
    block_destinations=frozenset({"evil.example"}),
)
receipt = plane.activate(operator, command, activated_at=10)
gateway.observe(plane.snapshot, observed_at=11)
print(json.dumps(asdict(receipt), indent=2, default=lambda item: item.value))
assert receipt.outcome is ks.Outcome.ALLOW
assert plane.snapshot.epoch == 1
"""),
        markdown("e02-tamper", """
## 2. Reject tamper, skip, replay, and rollback

Integrity protects the command content. Epoch ordering protects state history.
An old `active` snapshot cannot overwrite containment, and same-epoch content
conflict is rejected rather than resolved with last-writer-wins.
"""),
        code("e02-tamper-run", """
tamper_plane, tamper_operator, _, point = ks.build_system()
valid = ks.signed_command(tamper_plane, command_id="valid:1", epoch=1,
                          mode=ks.Mode.READ_ONLY,
                          revoke=frozenset({ks.Capability.WRITE}))
tampered = replace(valid, mode=ks.Mode.STOPPED)
tampered_result = tamper_plane.activate(tamper_operator, tampered, activated_at=10)
skipped = ks.signed_command(tamper_plane, command_id="skip:2", epoch=2,
                            mode=ks.Mode.STOPPED)
skip_result = tamper_plane.activate(tamper_operator, skipped, activated_at=10)
print({"tampered": tampered_result.reason, "skipped": skip_result.reason})
assert tampered_result.reason == "invalid-command-signature"
assert skip_result.reason == "non-monotonic-epoch"
"""),
        markdown("e02-boundaries", """
## 3. Enforce at scheduling and effect time

The queue carries a request, not durable authority. Both boundaries deny the
revoked write. The second check closes the race where revocation happens after
scheduling but before provider dispatch.
"""),
        code("e02-boundaries-run", """
decisions = [
    gateway.authorize(principal, ks.Capability.WRITE, destination="case-store",
                      now=12, boundary=boundary)
    for boundary in ("schedule", "effect")
]
print([asdict(item) for item in decisions])
assert all(item.outcome is ks.Outcome.DENY for item in decisions)
"""),
        markdown("e02-degrade", """
## 4. Preserve useful diagnostics without bypassing policy

Read-only mode retains one diagnostic capability, but the request still needs
authentication, the correct tenant, scope, current policy, a permitted
destination, and a fresh enough control view.
"""),
        code("e02-degrade-run", """
valid_read = gateway.authorize(principal, ks.Capability.DIAGNOSTIC_READ,
                               destination="case-store", now=12, boundary="effect")
cross_tenant = gateway.authorize(replace(principal, tenant="south"),
                                 ks.Capability.DIAGNOSTIC_READ,
                                 destination="case-store", now=12, boundary="effect")
blocked = gateway.authorize(principal, ks.Capability.DIAGNOSTIC_READ,
                            destination="evil.example", now=12, boundary="effect")
print({"valid": valid_read.reason, "cross_tenant": cross_tenant.reason,
       "blocked_destination": blocked.reason})
assert valid_read.outcome is ks.Outcome.ALLOW
assert cross_tenant.outcome is blocked.outcome is ks.Outcome.DENY
"""),
        markdown("e02-stale", """
## 5. Fail safely under stale distribution

This worker saw only epoch 0 and exceeded its freshness budget. It must not
infer that `active` is still safe. Deterministic logical time makes the
boundary test fast and reproducible.
"""),
        code("e02-stale-run", """
stale = ks.EnforcementPoint("stale-worker", "north", "support-7", max_staleness=5)
stale.observe(ks.ControlSnapshot("north", "support-7", 0, 0, ks.Mode.ACTIVE,
                                 frozenset(), frozenset(), ()), observed_at=0)
stale_write = stale.authorize(principal, ks.Capability.WRITE,
                              destination="case-store", now=20, boundary="effect")
print(asdict(stale_write))
assert stale_write.reason == "control-snapshot-stale"
"""),
        markdown("e02-inflight", """
## 6. Preserve `UNKNOWN` for non-cancelable in-flight work

The provider has no cancel primitive. Containment cannot honestly label the
operation safe, so it becomes unknown. Authoritative lookup using the original
logical operation ID resolves it without a duplicate dispatch.
"""),
        code("e02-inflight-run", """
provider = ks.SyntheticProvider(supports_cancel=False)
effect = provider.dispatch(ks.EffectRecord(
    "operation:42", ks.Capability.WRITE, "case-store", prepared_at=9))
provider.contain(effect)
before = effect.state
provider.reconcile(effect)
print({"after_containment": before.value, "after_reconcile": effect.state.value})
assert before is ks.EffectState.UNKNOWN
assert effect.state is ks.EffectState.CANCELED
"""),
        markdown("e02-committed", """
## 7. Do not claim rollback of a committed effect

If the provider confirms commit, a kill switch cannot erase it. A compensating
transaction would be a separate, newly authorized effect with its own receipt.
"""),
        code("e02-committed-run", """
committing = ks.SyntheticProvider(supports_cancel=True)
committed = committing.dispatch(ks.EffectRecord(
    "operation:committed", ks.Capability.WRITE, "case-store", 9), commit=True)
committing.contain(committed)
print({"state_after_kill_switch": committed.state.value})
assert committed.state is ks.EffectState.COMMITTED
"""),
        markdown("e02-recovery", """
## 8. Recover only under separate, single-use approval

An incident commander cannot simply set the old state back to active. A
different recovery approver binds one short-lived plan to the incident and the
exact epoch transition.
"""),
        code("e02-recovery-run", """
bypass = ks.signed_command(plane, command_id="recover:bypass", epoch=2,
                           mode=ks.Mode.ACTIVE,
                           restore=frozenset({ks.Capability.WRITE}))
denied = plane.activate(operator, bypass, activated_at=20)

approver = ks.Operator("risk:north:2", "north", frozenset({"recovery_approver"}))
plan = ks.RecoveryPlan("plan:1", "incident-2026-104", "north", "support-7",
                       1, 2, approver.subject, expires_at=30)
plane.approve_recovery(plan, approver)
recovery = ks.signed_command(plane, command_id="recover:approved", epoch=2,
                             mode=ks.Mode.ACTIVE,
                             restore=frozenset({ks.Capability.WRITE}),
                             recovery_plan_id=plan.plan_id)
approved = plane.activate(operator, recovery, activated_at=20)
print({"bypass": denied.reason, "approved": approved.reason,
       "new_epoch": plane.snapshot.epoch})
assert denied.outcome is ks.Outcome.DENY
assert approved.outcome is ks.Outcome.ALLOW
"""),
        markdown("e02-propagation", """
## 9. Measure propagation from authoritative activation

Use every expected enforcement point in the denominator. The individual
latencies reveal the laggard that a mean could hide.
"""),
        code("e02-propagation-run", """
propagation = ks.propagation_report(
    ks.ControlSnapshot("north", "support-7", 7, 100, ks.Mode.STOPPED,
                       frozenset(), frozenset(), ("drill",)),
    {"scheduler": 100, "gateway": 102, "worker": 105}, deadline=3)
print(json.dumps(propagation, indent=2))
assert propagation["within_slo"] == 2
assert propagation["expected"] == 3
"""),
        markdown("e02-evaluation", """
## 10. Keep valid, attack, boundary, and failure populations separate

Utility cannot average away harm. Unknown evidence cannot be counted as a safe
outcome. Exact denominators make the report independently reproducible.
"""),
        code("e02-evaluation-run", """
report = ks.evaluate_controls()
print(json.dumps(asdict(report), indent=2))
assert (report.valid_cases, report.attack_cases,
        report.boundary_cases, report.failure_cases) == (1, 4, 1, 2)
assert report.valid_diagnostic_retention_rate == 1
assert report.unsafe_effect_rate == report.recovery_bypass_rate == 0
"""),
        markdown("e02-sdk", """
## 11. Use the real OpenFeature SDK without granting it security authority

OpenFeature standardizes typed flag evaluation, context, providers, hooks, and
provider lifecycle. The adapter waits for provider readiness and uses a
fail-safe `False` default. The application still owns trusted epoch metadata,
operator/tenant authorization, command integrity, and effect reconciliation.
"""),
        code("e02-sdk-run", """
import openfeature_adapter

sdk_proof = openfeature_adapter.run_demo()
print(json.dumps(sdk_proof, indent=2))
assert sdk_proof["writes_enabled"] is False
assert sdk_proof["diagnostics_enabled"] is True
assert sdk_proof["epoch_from_trusted_envelope"] == 7
assert sdk_proof["sdk_is_security_authority"] is False
"""),
        markdown("e02-production", """
## Production upgrade and checkpoint

Replace the HMAC fixture with protected signing or mTLS, memory state with a
highly available versioned store and authenticated distribution, static scopes
with current identity/resource policy, and the synthetic provider with its
idempotency, cancellation, status, and receipt APIs.

**Checkpoint:** add a retrieval-only degradation mode. Test cross-tenant
diagnostics, stale state, replay, non-cancelable retrieval, and expired recovery.
Report propagation across scheduler, retrieval gateway, MCP host, and egress.
Name the authoritative source for identity, command, policy, effect outcome, and
audit evidence. Pass only if no unknown is counted safe and valid diagnostics
remain useful.
"""),
    ]
    return notebook


def main() -> None:
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")


if __name__ == "__main__":
    main()
