"""Generate the Enterprise 05 notebook deterministically."""
from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "release_readiness.ipynb"


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
        markdown("e05-title", """
# Enterprise 05 — Security Release Gates and Production Readiness

**Goal:** turn exact, current, authenticated evidence into a bounded production
decision, then prove the canary, promotion, or rollback from provider state.

This notebook is deterministic, credential-free, and makes no external calls.
It exercises the real Pydantic v2 SDK at the untrusted payload boundary.

![Evidence admission, release decision, and verified progressive delivery](architecture.svg)
"""),
        markdown("e05-thesis", """
## Security thesis

An artifact's presence, a green CI badge, an average score, a reviewer title,
or an LLM recommendation is not production authority. Trusted application code
must authenticate each exact artifact, enforce freshness and coverage, retain
non-compensable severe blockers, bind one approval to one plan and version,
and verify the external rollout or rollback.
"""),
        code("e05-imports", """
from dataclasses import asdict, replace
import json

import release_fixtures as fixtures
import lab
import pydantic_adapter as adapter
import release_readiness as rr

scenario = fixtures.build_scenario()
print({"release": scenario.record.release_id,
       "candidate": scenario.record.candidate_digest,
       "evidence": len(scenario.store.evidence)})
"""),
        markdown("e05-schema", """
## 1. Parse hostile JSON with Pydantic v2

The adapter rejects unknown fields and integer coercion while translating
known enum strings. Schema validity does not authenticate the producer or
prove that a test ran.
"""),
        code("e05-schema-run", """
item = next(iter(scenario.store.evidence.values()))
payload = asdict(item)
payload["kind"] = item.kind.value
payload["result"] = item.result.value
parsed = adapter.parse_evidence(payload)
print({"id": parsed.evidence_id, "kind": parsed.kind.value, "coverage": parsed.coverage})
assert parsed == item
"""),
        markdown("e05-admission", """
## 2. Admit evidence through the producer registry

Admission binds producer, key, tenant, allowed evidence kind, proof, counts,
owner, source, and time shape. The deterministic HMAC fixture is not a
production trust service; replace it with KMS/HSM-backed attestations.
"""),
        code("e05-admission-run", """
keyring = adapter.fixture_keyring()
producer = rr.TrustedProducer("ci:north", "north", "ci-evidence-2026-11", fixtures.ALL_KINDS)
store = rr.EvidenceStore({producer.producer_id: producer}, keyring)
receipt = store.admit(fixtures.make_evidence(keyring)[0], now=120)
print(asdict(receipt))
assert receipt.status is rr.Admission.ADMITTED
"""),
        markdown("e05-dossier", """
## 3. Evaluate the exact evidence dossier

Every required evidence kind applies to the same release digest, tenant,
environment, and policy version. Coverage uses total passed/checked counts;
the gate also exposes age and severe failures separately.
"""),
        code("e05-dossier-run", """
decision, plan, approval = fixtures.approved_release(scenario)
print(json.dumps(asdict(decision), indent=2, default=lambda value: value.value))
assert decision.state is rr.GateState.READY
assert decision.evidence_coverage == 1.0
assert len(decision.evidence_ids) == len(rr.EvidenceKind)
"""),
        markdown("e05-presence", """
## 4. Defeat the presence-only bypass

A passing label with 1/100 exercised checks is still insufficient. Coverage is
an explicit requirement, not an optional annotation.
"""),
        code("e05-presence-run", """
shallow = fixtures.build_scenario()
evidence_id = "evidence:integration-test:500"
original = shallow.store.evidence[evidence_id]
changed = shallow.keyring.sign_evidence(
    replace(original, checked=100, passed=1, proof=""), original.key_id)
shallow.store.evidence[evidence_id] = changed
shallow.store.evidence_digests[evidence_id] = rr.digest(rr.evidence_payload(changed))
shallow_decision = shallow.gate.evaluate(
    release_digest=shallow.record.candidate_digest, tenant="north", environment="production",
    policy_version=shallow.executor.current_policy_version, now=120)
print(shallow_decision.blockers)
assert "coverage:integration-test" in shallow_decision.blockers
"""),
        markdown("e05-severe", """
## 5. Keep severe outcomes outside averages

One observed unauthorized effect remains a hard blocker even if every other
case passed. The numerator and the exact failure stay visible.
"""),
        code("e05-severe-run", """
severe = fixtures.build_scenario()
evidence_id = "evidence:adversarial-eval:500"
original = severe.store.evidence[evidence_id]
changed = severe.keyring.sign_evidence(
    replace(original, severe_failures=1, result=rr.EvidenceResult.FAIL, proof=""),
    original.key_id)
severe.store.evidence[evidence_id] = changed
severe.store.evidence_digests[evidence_id] = rr.digest(rr.evidence_payload(changed))
severe_decision = severe.gate.evaluate(
    release_digest=severe.record.candidate_digest, tenant="north", environment="production",
    policy_version=severe.executor.current_policy_version, now=120)
print({"state": severe_decision.state.value, "blockers": severe_decision.blockers})
assert "severe-failure" in severe_decision.blockers
"""),
        markdown("e05-exception", """
## 6. Bound risk acceptance without weakening hard blockers

An exception is authenticated, exact-release, exact-environment, owned, and
expiring. It may remove one explicitly waivable blocker; it cannot waive a
severe failure or a non-waivable requirement.
"""),
        code("e05-exception-run", """
exception = fixtures.signed_exception(severe, "severe-failure")
exception_decision = severe.gate.evaluate(
    release_digest=severe.record.candidate_digest, tenant="north", environment="production",
    policy_version=severe.executor.current_policy_version, now=120,
    exceptions=(exception,))
print(exception_decision.blockers)
assert "severe-failure" in exception_decision.blockers
assert "non-waivable:severe-failure" in exception_decision.blockers
"""),
        markdown("e05-plan", """
## 7. Bind one plan to one evidence snapshot

The plan fixes candidate and stable digests, environment, autonomy, policy,
evidence-set digest, evaluation time, canary thresholds, rollback target, and
stable logical operation ID. Editing a field invalidates the plan digest.
"""),
        code("e05-plan-run", """
print({"plan": plan.plan_id, "digest": plan.plan_digest,
       "evidence": plan.evidence_set_digest, "canary": plan.canary_percent})
assert plan.plan_digest == rr.digest(
    {key: value for key, value in plan.__dict__.items() if key != "plan_digest"})
assert approval.plan_digest == plan.plan_digest
"""),
        markdown("e05-promote", """
## 8. Execute and verify a safe canary

The operator and approver are distinct. Current authorization is checked
before the single-use approval is consumed. Promotion follows provider-state
verification and exact safety, error, latency, and cost thresholds.
"""),
        code("e05-promote-run", """
result = scenario.executor.execute(
    scenario.record, plan, approval, scenario.actor, scenario.authorizer,
    scenario.provider, now=120)
print(json.dumps(asdict(result), indent=2, default=lambda value: value.value))
assert result.state is rr.ReleaseState.PROMOTED
assert result.deployment_verified
assert scenario.provider.deployment_effects == 1
"""),
        markdown("e05-rollback", """
## 9. Roll back a failed canary and verify the stable digest

A critical canary outcome triggers the stable rollback operation. A rollback
request is not proof: the course queries the provider and keeps
`ROLLBACK_UNKNOWN` when that postcondition cannot be established.
"""),
        code("e05-rollback-run", """
unsafe = fixtures.build_scenario()
unsafe.provider.metrics[unsafe.record.candidate_digest] = rr.CanaryMetrics(
    100, 1, 0.01, 0.99, 430, 0.08)
_, unsafe_plan, unsafe_approval = fixtures.approved_release(unsafe)
rolled_back = unsafe.executor.execute(
    unsafe.record, unsafe_plan, unsafe_approval, unsafe.actor,
    unsafe.authorizer, unsafe.provider, now=120)
print(asdict(rolled_back))
assert rolled_back.state is rr.ReleaseState.ROLLED_BACK
assert rolled_back.rollback_verified
"""),
        markdown("e05-unknown", """
## 10. Preserve timeout-after-commit as unknown

If the provider commits the canary then the response times out, a blind retry
can duplicate a rollout. The stable operation ID supports later
reconciliation; the uncertain turn ends explicitly unknown.
"""),
        code("e05-unknown-run", """
timeout = fixtures.build_scenario()
_, timeout_plan, timeout_approval = fixtures.approved_release(timeout)
timeout.provider.timeout_after_commit.add(timeout_plan.logical_operation_id)
unknown = timeout.executor.execute(
    timeout.record, timeout_plan, timeout_approval, timeout.actor,
    timeout.authorizer, timeout.provider, now=120)
observation = timeout.provider.query(timeout_plan.logical_operation_id)
print({"state": unknown.state.value, "provider": observation.status.value,
       "effects": timeout.provider.deployment_effects})
assert unknown.state is rr.ReleaseState.OUTCOME_UNKNOWN
assert observation.status is rr.ProviderStatus.CANARY
assert timeout.provider.deployment_effects == 1
"""),
        markdown("e05-evaluation", """
## 11. Evaluate valid, attack, boundary, and failure populations

Report denominators, severe escapes, stale-evidence rejection, rollback
success, duplicate effects, and false blocks. Never collapse them into one
comforting score.
"""),
        code("e05-evaluation-run", """
evaluation = lab.evaluate_controls()
print(json.dumps(asdict(evaluation), indent=2))
assert evaluation.severe_failure_escape_rate == 0.0
assert evaluation.stale_evidence_rejection_rate == 1.0
assert evaluation.rollback_success_rate == 1.0
assert evaluation.duplicate_deployment_effects == 0
"""),
        markdown("e05-checkpoint", """
## Checkpoint

A release passes 999 of 1,000 adversarial cases. The single failure is a
verified cross-tenant write. The build has valid provenance and a senior
reviewer approves an exception. Is the release production-ready?

**Expected reasoning:** No. The forbidden outcome is an observed severe
invariant violation and remains a non-waivable blocker outside aggregate
scores. Preserve the evidence, fix the control, rerun the exact release-bound
campaign, and create a new approval only after the current gate is ready.
"""),
    ]
    return notebook


if __name__ == "__main__":
    nbf.write(build_notebook(), OUTPUT)
    print(f"wrote {OUTPUT.name}")
