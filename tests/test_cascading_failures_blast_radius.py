"""Security and reliability invariants for Advanced 03."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


COURSE = (
    Path(__file__).parents[1]
    / "curriculum/roadmap/advanced/03-cascading-failures-and-blast-radius-control"
)
SPEC = importlib.util.spec_from_file_location("advanced_03_cascade_lab", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


def scenario_with_run():
    controller, identities = LAB.build_scenario()
    run = LAB.start_run(controller, identities)
    return controller, identities, run


def successful_attempt(target: str = "ticket"):
    controller, identities, run = scenario_with_run()
    dispatched, observed = LAB.dispatch_and_observe(
        controller,
        identities,
        run,
        target,
        attempt_id=f"attempt:{target}:success",
        outcome=LAB.Outcome.SUCCESS,
        step=1,
    )
    assert dispatched.attempt and observed.allowed
    return controller, identities, run, dispatched.attempt


def test_unsafe_baseline_exposes_combinatorial_retry_amplification() -> None:
    comparison = LAB.unsafe_naive_cascade(retries_per_layer=3, retrying_layers=3)
    assert comparison.unsafe_attempts == 64
    assert comparison.unsafe_affected_components == 4
    assert comparison.unsafe_unauthorized_effects == 2
    assert comparison.controlled_attempts == 1
    assert comparison.controlled_unauthorized_effects == 0


@pytest.mark.parametrize(
    ("identity_change", "root_change", "reason"),
    [
        ({"authenticated": False}, {}, "coordinator-unauthenticated"),
        ({"workload_id": "spiffe://attacker"}, {}, "coordinator-identity-binding"),
        ({}, {"tenant": "south"}, "tenant"),
        ({}, {"task_type": "unbounded"}, "root-task-type"),
    ],
)
def test_run_start_uses_authenticated_server_owned_scope(
    identity_change: dict[str, object],
    root_change: dict[str, object],
    reason: str,
) -> None:
    controller, identities = LAB.build_scenario()
    identity = replace(identities["supervisor"], **identity_change)
    root = replace(LAB.root_task(), **root_change)
    decision = controller.start(identity, root, step=0)
    assert not decision.allowed
    assert decision.reason == reason


def test_worker_cannot_recursively_delegate_or_widen_depth() -> None:
    controller, identities, run = scenario_with_run()
    recursive = controller.dispatch(
        identities["research"],
        run.root.run_id,
        LAB.dispatch_for(
            run, identities, "billing", attempt_id="attempt:recursive"
        ),
        step=1,
    )
    deep = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        LAB.dispatch_for(
            run, identities, "research", attempt_id="attempt:deep", depth=2
        ),
        step=2,
    )
    assert recursive.reason == "edge-not-allowed"
    assert deep.reason == "depth-budget"
    assert not run.attempts


def test_per_component_queue_is_a_bulkhead() -> None:
    controller, identities, run = scenario_with_run()
    for index in (1, 2):
        decision = controller.dispatch(
            identities["supervisor"],
            run.root.run_id,
            LAB.dispatch_for(
                run,
                identities,
                "research",
                attempt_id=f"attempt:queue:{index}",
                logical_id=f"logical:queue:{index}",
            ),
            step=index,
        )
        assert decision.allowed
    denied = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        LAB.dispatch_for(
            run,
            identities,
            "research",
            attempt_id="attempt:queue:3",
            logical_id="logical:queue:3",
        ),
        step=3,
    )
    assert denied.state is LAB.DecisionState.STOP
    assert denied.reason == "component-queue-full"
    assert len(run.queues["research"]) == 2
    assert all(not queue for name, queue in run.queues.items() if name != "research")


def test_only_transient_failures_receive_a_bounded_retry() -> None:
    controller, identities, run = scenario_with_run()
    first, _ = LAB.dispatch_and_observe(
        controller,
        identities,
        run,
        "billing",
        attempt_id="attempt:retry:1",
        logical_id="logical:retry",
        outcome=LAB.Outcome.TRANSIENT_FAILURE,
        step=1,
    )
    retry, _ = LAB.dispatch_and_observe(
        controller,
        identities,
        run,
        "billing",
        attempt_id="attempt:retry:2",
        logical_id="logical:retry",
        retry_of=first.attempt.proposal.attempt_id,
        outcome=LAB.Outcome.SUCCESS,
        step=3,
    )
    assert retry.allowed and run.retry_budget_used == 1

    too_many = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        LAB.dispatch_for(
            run,
            identities,
            "billing",
            attempt_id="attempt:retry:3",
            logical_id="logical:retry",
            retry_of=retry.attempt.proposal.attempt_id,
        ),
        step=5,
    )
    assert too_many.reason == "retry-not-transient"


def test_circuit_breaker_is_not_a_concurrency_limit_and_isolates_failure() -> None:
    controller, identities, run = scenario_with_run()
    for index in (1, 2):
        LAB.dispatch_and_observe(
            controller,
            identities,
            run,
            "billing",
            attempt_id=f"attempt:breaker:{index}",
            logical_id=f"logical:breaker:{index}",
            outcome=LAB.Outcome.TRANSIENT_FAILURE,
            step=index * 2 - 1,
        )
    assert run.circuits["billing"].state is LAB.BreakerState.OPEN

    blocked = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        LAB.dispatch_for(
            run,
            identities,
            "billing",
            attempt_id="attempt:breaker:3",
            logical_id="logical:breaker:3",
        ),
        step=5,
    )
    allowed = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        LAB.dispatch_for(
            run,
            identities,
            "research",
            attempt_id="attempt:isolated",
        ),
        step=6,
    )
    assert blocked.reason == "circuit-open"
    assert allowed.allowed


def test_poison_containment_stops_queued_work_and_effects_immediately() -> None:
    controller, identities = LAB.build_scenario()
    run = LAB.start_run(controller, identities)
    queued = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        LAB.dispatch_for(run, identities, "ticket", attempt_id="attempt:queued"),
        step=1,
    )
    assert queued.allowed
    poison, contained = LAB.dispatch_and_observe(
        controller,
        identities,
        run,
        "research",
        attempt_id="attempt:poison",
        logical_id="logical:poison",
        outcome=LAB.Outcome.POISONED,
        step=2,
    )
    assert poison.allowed
    assert contained.state is LAB.DecisionState.STOP
    assert run.state is LAB.RunState.CONTAINED
    assert run.stop_latency_steps == 0
    assert all(not queue for queue in run.queues.values())

    effect = controller.authorize_effect(
        identities["ticket"],
        run.root.run_id,
        LAB.EffectProposal(
            "operation:blocked",
            "create-internal-ticket",
            "case:north:42",
            "attempt:queued",
        ),
        step=3,
    )
    assert effect.state is LAB.DecisionState.STOP
    assert not run.effects


def test_effect_is_atomic_idempotent_and_bound_to_successful_work() -> None:
    controller, identities, run, attempt = successful_attempt("ticket")
    proposal = LAB.EffectProposal(
        "operation:ticket",
        "create-internal-ticket",
        "case:north:42",
        attempt.proposal.attempt_id,
    )
    with ThreadPoolExecutor(max_workers=12) as pool:
        decisions = list(
            pool.map(
                lambda _: controller.authorize_effect(
                    identities["ticket"], run.root.run_id, proposal, step=3
                ),
                range(24),
            )
        )
    assert all(decision.allowed for decision in decisions)
    assert sum(not decision.replayed for decision in decisions) == 1
    assert len(run.effects) == 1

    mutation = controller.authorize_effect(
        identities["ticket"],
        run.root.run_id,
        replace(proposal, target="case:north:99"),
        step=4,
    )
    assert mutation.reason == "effect-target"
    assert len(run.effects) == 1


def test_model_or_result_text_cannot_grant_an_effect() -> None:
    controller, identities, run, attempt = successful_attempt("research")
    decision = controller.authorize_effect(
        identities["research"],
        run.root.run_id,
        LAB.EffectProposal(
            "operation:export",
            "send-customer-message",
            "case:north:42",
            attempt.proposal.attempt_id,
        ),
        step=3,
    )
    assert not decision.allowed
    assert decision.reason == "effect-not-allowed"
    assert not run.effects


@pytest.mark.parametrize("dependency", ["policy", "ledger", "executor"])
def test_dependencies_fail_closed_without_effects(dependency: str) -> None:
    controller, identities = LAB.build_scenario()
    if dependency == "policy":
        controller.policy_available = False
        decision = controller.start(identities["supervisor"], LAB.root_task(), step=0)
        run = None
    else:
        run = LAB.start_run(controller, identities)
        if dependency == "ledger":
            controller.ledger_available = False
            decision = controller.dispatch(
                identities["supervisor"],
                run.root.run_id,
                LAB.dispatch_for(
                    run, identities, "ticket", attempt_id="attempt:dependency"
                ),
                step=1,
            )
        else:
            dispatched, _ = LAB.dispatch_and_observe(
                controller,
                identities,
                run,
                "ticket",
                attempt_id="attempt:dependency",
                outcome=LAB.Outcome.SUCCESS,
                step=1,
            )
            controller.effect_executor_available = False
            decision = controller.authorize_effect(
                identities["ticket"],
                run.root.run_id,
                LAB.EffectProposal(
                    "operation:dependency",
                    "create-internal-ticket",
                    "case:north:42",
                    dispatched.attempt.proposal.attempt_id,
                ),
                step=3,
            )
    assert decision.state is LAB.DecisionState.ERROR
    assert run is None or not run.effects


def test_receipts_are_complete_and_exclude_payloads_and_credentials() -> None:
    controller, identities, run = scenario_with_run()
    LAB.dispatch_and_observe(
        controller,
        identities,
        run,
        "research",
        attempt_id="attempt:audit",
        outcome=LAB.Outcome.SUCCESS,
        step=1,
    )
    serialized = json.dumps([asdict(receipt) for receipt in controller.receipts], default=str)
    assert "case 42 bounded support request" not in serialized
    assert "spiffe://" not in serialized
    assert all(receipt.receipt_id and receipt.policy_version for receipt in controller.receipts)


def test_evaluation_reports_populations_and_metric_denominators() -> None:
    report, cases = LAB.evaluate_controls()
    assert (report.total_cases, report.valid_cases, report.attack_cases, report.failure_cases) == (
        20,
        5,
        12,
        3,
    )
    assert report.valid_completion_rate == 1.0
    assert report.attack_forbidden_effect_rate == 0.0
    assert report.failure_error_rate == 1.0
    assert report.max_affected_components == 3
    assert report.max_stop_latency_steps == 0
    assert report.controlled_retry_amplification == 2.0
    assert report.unsafe_retry_amplification == 64.0
    assert report.trace_completeness_rate == 1.0
    assert {case.population for case in cases} == {"valid", "attack", "failure"}


def test_architecture_spec_and_render_are_deterministic() -> None:
    specification = json.loads((COURSE / "architecture-spec.json").read_text())
    assert specification["id"] == "advanced-03-cascade-containment"
    assert len(specification["nodes"]) <= 12
    before = (COURSE / "architecture.svg").read_text()
    subprocess.run(
        [sys.executable, str(COURSE / "render_architecture.py")],
        check=True,
        capture_output=True,
        text=True,
    )
    assert (COURSE / "architecture.svg").read_text() == before
