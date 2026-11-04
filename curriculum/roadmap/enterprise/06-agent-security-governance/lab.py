"""Run the Enterprise 06 governance lifecycle and adversarial checks.

The lab keeps trusted policy in application code. Model output, catalog text,
schema validity, evidence labels, and reviewer titles are inputs rather than
governance authority.
"""
from dataclasses import asdict, dataclass, replace
import json

import governance as gov
import governance_fixtures as fixtures
import governance_pydantic_adapter


@dataclass(frozen=True)
class EvaluationReport:
    cases: int
    unsafe_authorizations: int
    stale_revision_rejection_rate: float
    severe_failure_rejection_rate: float
    approval_attack_rejection_rate: float
    false_blocks: int


def evaluate_controls() -> EvaluationReport:
    """Exercise valid, stale, severe, and authority-attack populations.

    Separate denominators make it impossible for a large happy-path set to hide
    one severe escape. These deterministic cases are a regression suite, not a
    claim that the policy covers every production risk.
    """
    record = fixtures.record()
    cases = 0
    unsafe_authorizations = 0
    false_blocks = 0

    valid_engine = fixtures.engine()
    valid = valid_engine.evaluate(record, gov.Lifecycle.AUTHORIZED, fixtures.NOW)
    cases += 1
    false_blocks += int(valid.state is not gov.DecisionState.READY)

    stale_rejected = 0
    for revision in (8, 9, 10):
        decision = fixtures.engine().evaluate(
            replace(record, revision=revision, change_digest=f"change-{revision}"),
            gov.Lifecycle.AUTHORIZED, fixtures.NOW)
        cases += 1
        stale_rejected += int(decision.state is not gov.DecisionState.READY)
        unsafe_authorizations += int(decision.state is gov.DecisionState.READY)

    severe_rejected = 0
    for severe_failures in (1, 2, 10):
        items = [fixtures.evidence("security-test", severe_failures=severe_failures)] + [
            fixtures.evidence(kind) for kind in ("threat-model", "privacy-review", "incident-drill")]
        decision = fixtures.engine(items).evaluate(
            record, gov.Lifecycle.AUTHORIZED, fixtures.NOW,
            [fixtures.exception("severe-failure")])
        cases += 1
        severe_rejected += int(decision.state is not gov.DecisionState.READY)
        unsafe_authorizations += int(decision.state is gov.DecisionState.READY)

    approval_attacks_rejected = 0
    attacks = (
        {"tenant": "south"},
        {"record_revision": 6},
        {"decision_digest": "attacker-selected"},
    )
    for attack in attacks:
        engine = fixtures.engine()
        decision = engine.evaluate(record, gov.Lifecycle.AUTHORIZED, fixtures.NOW)
        cases += 1
        try:
            engine.authorize(
                record, decision, fixtures.approval(decision, **attack),
                fixtures.operator(), fixtures.NOW)
        except PermissionError:
            approval_attacks_rejected += 1
        else:
            unsafe_authorizations += 1

    return EvaluationReport(
        cases=cases,
        unsafe_authorizations=unsafe_authorizations,
        stale_revision_rejection_rate=stale_rejected / 3,
        severe_failure_rejection_rate=severe_rejected / 3,
        approval_attack_rejection_rate=approval_attacks_rejected / len(attacks),
        false_blocks=false_blocks,
    )


def run_lab() -> dict:
    record = fixtures.record()
    parsed = governance_pydantic_adapter.parse_record(asdict(record))
    assert parsed == record

    engine = fixtures.engine()
    decision = engine.evaluate(record, gov.Lifecycle.AUTHORIZED, fixtures.NOW)
    assert decision.state is gov.DecisionState.READY
    approved = engine.authorize(
        record, decision, fixtures.approval(decision), fixtures.operator(), fixtures.NOW)
    assert approved.lifecycle is gov.Lifecycle.AUTHORIZED
    assert approved.revision == 8

    changed = replace(record, revision=8, tools=record.tools + ("refund.issue",), change_digest="change-8")
    stale = engine.evaluate(changed, gov.Lifecycle.AUTHORIZED, fixtures.NOW)
    assert stale.state is gov.DecisionState.INCOMPLETE

    severe_item = fixtures.evidence("security-test", severe_failures=1, passed=99)
    severe_engine = fixtures.engine([severe_item] + [
        fixtures.evidence(kind) for kind in ("threat-model", "privacy-review", "incident-drill")])
    severe = severe_engine.evaluate(
        record, gov.Lifecycle.AUTHORIZED, fixtures.NOW,
        [fixtures.exception("severe-failure")])
    assert "severe-failure" in severe.blockers

    evaluation = evaluate_controls()
    assert evaluation.unsafe_authorizations == 0
    assert evaluation.stale_revision_rejection_rate == 1.0
    assert evaluation.severe_failure_rejection_rate == 1.0
    assert evaluation.approval_attack_rejection_rate == 1.0
    assert evaluation.false_blocks == 0

    return {
        "parsed_record": parsed.agent_id,
        "decision": asdict(decision),
        "authorized_revision": approved.revision,
        "changed_record_state": stale.state.value,
        "severe_blockers": severe.blockers,
        "evaluation": asdict(evaluation),
    }


if __name__ == "__main__":
    print(json.dumps(run_lab(), indent=2, default=lambda value: value.value))
