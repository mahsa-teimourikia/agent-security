"""Credential-free cascade containment for a multi-agent support workflow.

The model may propose work. Trusted orchestration owns graph edges, tenant
scope, fan-out, depth, queues, retries, circuit state, containment, and effects.
Logical steps model ordering; they are not wall-clock latency measurements.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from hashlib import sha256
import json
from threading import Lock
from typing import Mapping


def _canonical(value: object) -> str:
    def normalize(item: object) -> object:
        if isinstance(item, Enum):
            return item.value
        if isinstance(item, (frozenset, set)):
            return sorted(normalize(part) for part in item)
        if isinstance(item, tuple):
            return [normalize(part) for part in item]
        if hasattr(item, "__dataclass_fields__"):
            return normalize(asdict(item))
        if isinstance(item, dict):
            return {str(key): normalize(val) for key, val in sorted(item.items())}
        if isinstance(item, list):
            return [normalize(part) for part in item]
        return item

    return json.dumps(normalize(value), separators=(",", ":"), sort_keys=True)


def _digest(value: object) -> str:
    return sha256(_canonical(value).encode()).hexdigest()


class DecisionState(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ERROR = "error"
    STOP = "stop"


class RunState(str, Enum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    CONTAINED = "contained"
    COMPLETE = "complete"
    ERROR = "error"


class Outcome(str, Enum):
    SUCCESS = "success"
    TRANSIENT_FAILURE = "transient-failure"
    PERMANENT_FAILURE = "permanent-failure"
    POISONED = "poisoned"


class BreakerState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"


@dataclass(frozen=True)
class WorkloadIdentity:
    subject: str
    tenant: str
    workload_id: str
    authenticated: bool = True


@dataclass(frozen=True)
class CascadePolicy:
    version: str
    identities: frozenset[tuple[str, str]]
    allowed_edges: frozenset[tuple[str, str]]
    task_types: Mapping[str, frozenset[str]]
    effect_permissions: Mapping[str, frozenset[str]]
    max_depth: int = 1
    max_fanout: int = 3
    max_dispatches: int = 5
    max_retries_per_logical: int = 1
    retry_budget: int = 2
    max_queue_per_component: int = 2
    breaker_threshold: int = 2
    max_affected_components: int = 3


@dataclass(frozen=True)
class RootTask:
    run_id: str
    task_id: str
    tenant: str
    task_type: str
    payload_digest: str


@dataclass(frozen=True)
class DispatchProposal:
    attempt_id: str
    logical_id: str
    parent_attempt_id: str
    target: str
    target_workload_id: str
    tenant: str
    task_type: str
    depth: int
    payload_digest: str
    retry_of: str | None = None


@dataclass(frozen=True)
class QueuedAttempt:
    run_id: str
    proposal: DispatchProposal
    sender: str
    sender_workload_id: str
    accepted_step: int


@dataclass(frozen=True)
class ExecutionObservation:
    attempt_id: str
    component: str
    component_workload_id: str
    tenant: str
    outcome: Outcome
    result_digest: str


@dataclass(frozen=True)
class EffectProposal:
    operation_id: str
    action: str
    target: str
    source_attempt_id: str


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    stage: str
    state: DecisionState
    reason: str
    run_id: str
    tenant: str
    component: str
    step: int
    policy_version: str
    affected_components: int
    dispatches: int
    retries: int
    attempt_id: str = ""
    operation_id: str = ""
    effect_id: str | None = None


@dataclass(frozen=True)
class ControlDecision:
    state: DecisionState
    reason: str
    receipt: Receipt
    attempt: QueuedAttempt | None = None
    effect_id: str | None = None
    replayed: bool = False

    @property
    def allowed(self) -> bool:
        return self.state is DecisionState.ALLOW


@dataclass
class Circuit:
    state: BreakerState = BreakerState.CLOSED
    failures: int = 0


@dataclass
class RunRecord:
    root: RootTask
    coordinator: str
    coordinator_workload_id: str
    state: RunState = RunState.ACTIVE
    attempts: dict[str, tuple[str, QueuedAttempt]] = field(default_factory=dict)
    observations: dict[str, tuple[str, ExecutionObservation]] = field(
        default_factory=dict
    )
    queues: dict[str, list[str]] = field(default_factory=dict)
    logical_attempts: dict[str, list[str]] = field(default_factory=dict)
    fanout_logicals: set[str] = field(default_factory=set)
    affected_components: set[str] = field(default_factory=set)
    retry_budget_used: int = 0
    circuits: dict[str, Circuit] = field(default_factory=dict)
    effects: dict[str, tuple[str, str]] = field(default_factory=dict)
    trigger_step: int | None = None
    contained_step: int | None = None

    @property
    def stop_latency_steps(self) -> int | None:
        if self.trigger_step is None or self.contained_step is None:
            return None
        return self.contained_step - self.trigger_step


@dataclass(frozen=True)
class ControlCase:
    name: str
    population: str
    family: str
    state: DecisionState
    safe: bool
    forbidden_effect: bool
    trace_complete: bool


@dataclass(frozen=True)
class CascadeComparison:
    unsafe_attempts: int
    unsafe_affected_components: int
    unsafe_unauthorized_effects: int
    unsafe_stop_latency_steps: int
    controlled_attempts: int
    controlled_affected_components: int
    controlled_unauthorized_effects: int
    controlled_stop_latency_steps: int


@dataclass(frozen=True)
class EvaluationReport:
    total_cases: int
    valid_cases: int
    attack_cases: int
    failure_cases: int
    valid_completion_rate: float
    attack_forbidden_effect_rate: float
    failure_error_rate: float
    max_affected_components: int
    max_stop_latency_steps: int
    controlled_retry_amplification: float
    unsafe_retry_amplification: float
    trace_completeness_rate: float


class CascadeController:
    """Reference monitor for work propagation and effects across a graph."""

    def __init__(self, policy: CascadePolicy) -> None:
        self.policy = policy
        self.policy_available = True
        self.ledger_available = True
        self.effect_executor_available = True
        self.runs: dict[str, RunRecord] = {}
        self.receipts: list[Receipt] = []
        self._lock = Lock()

    def _receipt(
        self,
        *,
        stage: str,
        state: DecisionState,
        reason: str,
        run_id: str,
        tenant: str,
        component: str,
        step: int,
        run: RunRecord | None,
        attempt_id: str = "",
        operation_id: str = "",
        effect_id: str | None = None,
    ) -> Receipt:
        receipt = Receipt(
            receipt_id=_digest(
                {
                    "stage": stage,
                    "run": run_id,
                    "reason": reason,
                    "attempt": attempt_id,
                    "operation": operation_id,
                    "sequence": len(self.receipts),
                }
            )[:20],
            stage=stage,
            state=state,
            reason=reason,
            run_id=run_id,
            tenant=tenant,
            component=component,
            step=step,
            policy_version=self.policy.version,
            affected_components=len(run.affected_components) if run else 0,
            dispatches=len(run.attempts) if run else 0,
            retries=run.retry_budget_used if run else 0,
            attempt_id=attempt_id,
            operation_id=operation_id,
            effect_id=effect_id,
        )
        self.receipts.append(receipt)
        return receipt

    def start(
        self,
        coordinator: WorkloadIdentity,
        root: RootTask,
        *,
        step: int,
    ) -> ControlDecision:
        if step < 0:
            raise ValueError("step must be non-negative")
        state, reason = DecisionState.ALLOW, "run-started"
        if not self.policy_available:
            state, reason = DecisionState.ERROR, "policy-unavailable"
        elif not self.ledger_available:
            state, reason = DecisionState.ERROR, "ledger-unavailable"
        elif not coordinator.authenticated:
            state, reason = DecisionState.DENY, "coordinator-unauthenticated"
        elif (coordinator.subject, coordinator.workload_id) not in self.policy.identities:
            state, reason = DecisionState.DENY, "coordinator-identity-binding"
        elif coordinator.subject != "supervisor":
            state, reason = DecisionState.DENY, "coordinator-role"
        elif not all(
            (root.run_id, root.task_id, root.tenant, root.task_type, root.payload_digest)
        ):
            state, reason = DecisionState.DENY, "root-contract"
        elif root.task_type != "support-triage":
            state, reason = DecisionState.DENY, "root-task-type"
        elif root.tenant != coordinator.tenant:
            state, reason = DecisionState.DENY, "tenant"

        with self._lock:
            existing = self.runs.get(root.run_id)
            if state is DecisionState.ALLOW and existing:
                existing_digest = _digest(
                    {
                        "root": existing.root,
                        "coordinator": existing.coordinator,
                        "workload": existing.coordinator_workload_id,
                    }
                )
                requested_digest = _digest(
                    {
                        "root": root,
                        "coordinator": coordinator.subject,
                        "workload": coordinator.workload_id,
                    }
                )
                if existing_digest != requested_digest:
                    state, reason = DecisionState.DENY, "run-replay-mismatch"
                else:
                    receipt = self._receipt(
                        stage="start",
                        state=DecisionState.ALLOW,
                        reason="idempotent-run",
                        run_id=root.run_id,
                        tenant=root.tenant,
                        component="supervisor",
                        step=step,
                        run=existing,
                    )
                    return ControlDecision(
                        DecisionState.ALLOW,
                        "idempotent-run",
                        receipt,
                        replayed=True,
                    )
            if state is DecisionState.ALLOW:
                self.runs[root.run_id] = RunRecord(
                    root=root,
                    coordinator=coordinator.subject,
                    coordinator_workload_id=coordinator.workload_id,
                    queues={name: [] for name in self.policy.task_types},
                    circuits={name: Circuit() for name in self.policy.task_types},
                )

        run = self.runs.get(root.run_id)
        receipt = self._receipt(
            stage="start",
            state=state,
            reason=reason,
            run_id=root.run_id,
            tenant=coordinator.tenant,
            component="supervisor",
            step=step,
            run=run,
        )
        return ControlDecision(state, reason, receipt)

    def dispatch(
        self,
        sender: WorkloadIdentity,
        run_id: str,
        proposal: DispatchProposal,
        *,
        step: int,
    ) -> ControlDecision:
        if step < 0:
            raise ValueError("step must be non-negative")
        run = self.runs.get(run_id)
        state, reason = DecisionState.ALLOW, "dispatch-admitted"
        attempt: QueuedAttempt | None = None
        replayed = False

        if not self.policy_available:
            state, reason = DecisionState.ERROR, "policy-unavailable"
        elif not self.ledger_available:
            state, reason = DecisionState.ERROR, "ledger-unavailable"
        elif run is None:
            state, reason = DecisionState.DENY, "run-unavailable"
        elif not sender.authenticated:
            state, reason = DecisionState.DENY, "sender-unauthenticated"
        elif (sender.subject, sender.workload_id) not in self.policy.identities:
            state, reason = DecisionState.DENY, "sender-identity-binding"
        elif run.state is RunState.CONTAINED:
            state, reason = DecisionState.STOP, "run-contained"
        elif run.state in {RunState.COMPLETE, RunState.ERROR}:
            state, reason = DecisionState.STOP, "run-terminal"
        elif proposal.tenant != run.root.tenant or sender.tenant != run.root.tenant:
            state, reason = DecisionState.DENY, "tenant"
        elif not all(
            (
                proposal.attempt_id,
                proposal.logical_id,
                proposal.parent_attempt_id,
                proposal.target,
                proposal.target_workload_id,
                proposal.task_type,
                proposal.payload_digest,
            )
        ):
            state, reason = DecisionState.DENY, "dispatch-contract"
        elif proposal.parent_attempt_id != run.root.task_id:
            state, reason = DecisionState.DENY, "parent-binding"
        elif (
            proposal.target,
            proposal.target_workload_id,
        ) not in self.policy.identities:
            state, reason = DecisionState.DENY, "target-identity-binding"
        elif (
            sender.workload_id,
            proposal.target_workload_id,
        ) not in self.policy.allowed_edges:
            state, reason = DecisionState.DENY, "edge-not-allowed"
        elif proposal.task_type not in self.policy.task_types.get(
            proposal.target, frozenset()
        ):
            state, reason = DecisionState.DENY, "task-type"
        elif proposal.payload_digest != run.root.payload_digest:
            state, reason = DecisionState.DENY, "payload-binding"
        elif proposal.depth > self.policy.max_depth:
            state, reason = DecisionState.DENY, "depth-budget"
        elif run.circuits[proposal.target].state is BreakerState.OPEN:
            state, reason = DecisionState.STOP, "circuit-open"

        if state is DecisionState.ALLOW and run:
            proposal_digest = _digest({"sender": sender, "proposal": proposal})
            with self._lock:
                existing = run.attempts.get(proposal.attempt_id)
                if existing:
                    if existing[0] != proposal_digest:
                        state, reason = DecisionState.DENY, "attempt-replay-mismatch"
                    else:
                        attempt = existing[1]
                        state, reason, replayed = (
                            DecisionState.ALLOW,
                            "idempotent-dispatch",
                            True,
                        )
                else:
                    logical_attempts = run.logical_attempts.get(
                        proposal.logical_id, []
                    )
                    is_retry = proposal.retry_of is not None
                    if is_retry:
                        prior = run.observations.get(proposal.retry_of or "")
                        if (
                            not logical_attempts
                            or proposal.retry_of not in logical_attempts
                            or prior is None
                        ):
                            state, reason = DecisionState.DENY, "retry-binding"
                        elif prior[1].outcome is not Outcome.TRANSIENT_FAILURE:
                            state, reason = DecisionState.DENY, "retry-not-transient"
                        elif (
                            len(logical_attempts) - 1
                            >= self.policy.max_retries_per_logical
                        ):
                            state, reason = DecisionState.STOP, "logical-retry-budget"
                        elif run.retry_budget_used >= self.policy.retry_budget:
                            state, reason = DecisionState.STOP, "run-retry-budget"
                    elif logical_attempts:
                        state, reason = DecisionState.DENY, "logical-id-collision"
                    elif len(run.fanout_logicals) >= self.policy.max_fanout:
                        state, reason = DecisionState.STOP, "fanout-budget"

                    if (
                        state is DecisionState.ALLOW
                        and len(run.attempts) >= self.policy.max_dispatches
                    ):
                        state, reason = DecisionState.STOP, "dispatch-budget"
                    if (
                        state is DecisionState.ALLOW
                        and proposal.target not in run.affected_components
                        and len(run.affected_components)
                        >= self.policy.max_affected_components
                    ):
                        state, reason = DecisionState.STOP, "component-budget"
                    if (
                        state is DecisionState.ALLOW
                        and len(run.queues[proposal.target])
                        >= self.policy.max_queue_per_component
                    ):
                        state, reason = DecisionState.STOP, "component-queue-full"

                    if state is DecisionState.ALLOW:
                        attempt = QueuedAttempt(
                            run_id,
                            proposal,
                            sender.subject,
                            sender.workload_id,
                            step,
                        )
                        run.attempts[proposal.attempt_id] = (
                            proposal_digest,
                            attempt,
                        )
                        run.logical_attempts.setdefault(
                            proposal.logical_id, []
                        ).append(proposal.attempt_id)
                        if is_retry:
                            run.retry_budget_used += 1
                        else:
                            run.fanout_logicals.add(proposal.logical_id)
                        run.affected_components.add(proposal.target)
                        run.queues[proposal.target].append(proposal.attempt_id)

        receipt = self._receipt(
            stage="dispatch",
            state=state,
            reason=reason,
            run_id=run_id,
            tenant=sender.tenant,
            component=proposal.target,
            step=step,
            run=run,
            attempt_id=proposal.attempt_id,
        )
        return ControlDecision(state, reason, receipt, attempt, replayed=replayed)

    def observe(
        self,
        worker: WorkloadIdentity,
        run_id: str,
        observation: ExecutionObservation,
        *,
        step: int,
    ) -> ControlDecision:
        if step < 0:
            raise ValueError("step must be non-negative")
        run = self.runs.get(run_id)
        state, reason = DecisionState.ALLOW, "result-admitted"
        if not self.ledger_available:
            state, reason = DecisionState.ERROR, "ledger-unavailable"
        elif run is None:
            state, reason = DecisionState.DENY, "run-unavailable"
        elif not worker.authenticated:
            state, reason = DecisionState.DENY, "worker-unauthenticated"
        elif (worker.subject, worker.workload_id) not in self.policy.identities:
            state, reason = DecisionState.DENY, "worker-identity-binding"
        elif run.state is RunState.CONTAINED:
            state, reason = DecisionState.STOP, "run-contained"
        elif observation.tenant != run.root.tenant or worker.tenant != run.root.tenant:
            state, reason = DecisionState.DENY, "tenant"
        elif not all(
            (
                observation.attempt_id,
                observation.component,
                observation.component_workload_id,
                observation.result_digest,
            )
        ):
            state, reason = DecisionState.DENY, "observation-contract"
        elif observation.component != worker.subject or (
            observation.component_workload_id != worker.workload_id
        ):
            state, reason = DecisionState.DENY, "worker-binding"

        if state is DecisionState.ALLOW and run:
            with self._lock:
                attempt_entry = run.attempts.get(observation.attempt_id)
                if attempt_entry is None:
                    state, reason = DecisionState.DENY, "attempt-unavailable"
                elif attempt_entry[1].proposal.target != observation.component:
                    state, reason = DecisionState.DENY, "attempt-component"
                else:
                    observation_digest = _digest(observation)
                    existing = run.observations.get(observation.attempt_id)
                    if existing:
                        if existing[0] != observation_digest:
                            state, reason = (
                                DecisionState.DENY,
                                "observation-replay-mismatch",
                            )
                        else:
                            state, reason = (
                                DecisionState.ALLOW,
                                "idempotent-observation",
                            )
                    elif observation.attempt_id not in run.queues[
                        observation.component
                    ]:
                        state, reason = DecisionState.DENY, "queue-binding"
                    else:
                        run.queues[observation.component].remove(
                            observation.attempt_id
                        )
                        run.observations[observation.attempt_id] = (
                            observation_digest,
                            observation,
                        )
                        circuit = run.circuits[observation.component]
                        if observation.outcome is Outcome.SUCCESS:
                            circuit.failures = 0
                            reason = "result-admitted"
                        elif observation.outcome is Outcome.TRANSIENT_FAILURE:
                            run.state = RunState.DEGRADED
                            circuit.failures += 1
                            reason = "transient-failure"
                            if circuit.failures >= self.policy.breaker_threshold:
                                circuit.state = BreakerState.OPEN
                                reason = "circuit-opened"
                        elif observation.outcome is Outcome.PERMANENT_FAILURE:
                            run.state = RunState.DEGRADED
                            circuit.failures += 1
                            reason = "permanent-failure"
                        else:
                            run.trigger_step = step
                            run.contained_step = step
                            run.state = RunState.CONTAINED
                            for queue in run.queues.values():
                                queue.clear()
                            state, reason = DecisionState.STOP, "poison-contained"

        receipt = self._receipt(
            stage="observation",
            state=state,
            reason=reason,
            run_id=run_id,
            tenant=worker.tenant,
            component=observation.component,
            step=step,
            run=run,
            attempt_id=observation.attempt_id,
        )
        return ControlDecision(state, reason, receipt)

    def contain(self, run_id: str, *, reason: str, step: int) -> ControlDecision:
        if step < 0:
            raise ValueError("step must be non-negative")
        run = self.runs.get(run_id)
        state, result_reason = DecisionState.STOP, "run-contained"
        if not self.ledger_available:
            state, result_reason = DecisionState.ERROR, "ledger-unavailable"
        elif run is None:
            state, result_reason = DecisionState.DENY, "run-unavailable"
        elif not reason:
            state, result_reason = DecisionState.DENY, "containment-reason"
        else:
            with self._lock:
                if run.trigger_step is None:
                    run.trigger_step = step
                run.contained_step = step
                run.state = RunState.CONTAINED
                for queue in run.queues.values():
                    queue.clear()
        receipt = self._receipt(
            stage="containment",
            state=state,
            reason=result_reason,
            run_id=run_id,
            tenant=run.root.tenant if run else "",
            component="control-plane",
            step=step,
            run=run,
        )
        return ControlDecision(state, result_reason, receipt)

    def authorize_effect(
        self,
        worker: WorkloadIdentity,
        run_id: str,
        proposal: EffectProposal,
        *,
        step: int,
    ) -> ControlDecision:
        if step < 0:
            raise ValueError("step must be non-negative")
        run = self.runs.get(run_id)
        state, reason = DecisionState.ALLOW, "effect-authorized"
        effect_id: str | None = None
        replayed = False
        if not self.policy_available:
            state, reason = DecisionState.ERROR, "policy-unavailable"
        elif not self.ledger_available:
            state, reason = DecisionState.ERROR, "ledger-unavailable"
        elif not self.effect_executor_available:
            state, reason = DecisionState.ERROR, "effect-executor-unavailable"
        elif run is None:
            state, reason = DecisionState.DENY, "run-unavailable"
        elif not worker.authenticated:
            state, reason = DecisionState.DENY, "worker-unauthenticated"
        elif run.state is RunState.CONTAINED:
            state, reason = DecisionState.STOP, "run-contained"
        elif worker.tenant != run.root.tenant:
            state, reason = DecisionState.DENY, "tenant"
        elif (worker.subject, worker.workload_id) not in self.policy.identities:
            state, reason = DecisionState.DENY, "worker-identity-binding"
        elif not all(
            (
                proposal.operation_id,
                proposal.action,
                proposal.target,
                proposal.source_attempt_id,
            )
        ):
            state, reason = DecisionState.DENY, "effect-contract"
        elif proposal.action not in self.policy.effect_permissions.get(
            worker.subject, frozenset()
        ):
            state, reason = DecisionState.DENY, "effect-not-allowed"
        elif proposal.target != "case:north:42":
            state, reason = DecisionState.DENY, "effect-target"

        if state is DecisionState.ALLOW and run:
            with self._lock:
                attempt = run.attempts.get(proposal.source_attempt_id)
                observation = run.observations.get(proposal.source_attempt_id)
                if attempt is None or observation is None:
                    state, reason = DecisionState.DENY, "effect-source-unavailable"
                elif attempt[1].proposal.target != worker.subject:
                    state, reason = DecisionState.DENY, "effect-source-binding"
                elif observation[1].outcome is not Outcome.SUCCESS:
                    state, reason = DecisionState.DENY, "effect-source-failed"
                else:
                    operation_digest = _digest(
                        {"worker": worker, "proposal": proposal}
                    )
                    existing = run.effects.get(proposal.operation_id)
                    if existing:
                        if existing[0] != operation_digest:
                            state, reason = (
                                DecisionState.DENY,
                                "operation-replay-mismatch",
                            )
                        else:
                            effect_id = existing[1]
                            reason, replayed = "idempotent-effect", True
                    else:
                        effect_id = _digest(
                            {
                                "run": run_id,
                                "operation": proposal.operation_id,
                                "action": proposal.action,
                            }
                        )[:20]
                        run.effects[proposal.operation_id] = (
                            operation_digest,
                            effect_id,
                        )

        receipt = self._receipt(
            stage="effect",
            state=state,
            reason=reason,
            run_id=run_id,
            tenant=worker.tenant,
            component=worker.subject,
            step=step,
            run=run,
            attempt_id=proposal.source_attempt_id,
            operation_id=proposal.operation_id,
            effect_id=effect_id,
        )
        return ControlDecision(
            state,
            reason,
            receipt,
            effect_id=effect_id,
            replayed=replayed,
        )

    def complete(self, run_id: str, *, step: int) -> ControlDecision:
        if step < 0:
            raise ValueError("step must be non-negative")
        run = self.runs.get(run_id)
        state, reason = DecisionState.ALLOW, "run-complete"
        if run is None:
            state, reason = DecisionState.DENY, "run-unavailable"
        elif run.state is RunState.CONTAINED:
            state, reason = DecisionState.STOP, "run-contained"
        elif any(run.queues.values()):
            state, reason = DecisionState.DENY, "work-outstanding"
        elif not run.logical_attempts or any(
            not any(
                attempt_id in run.observations
                and run.observations[attempt_id][1].outcome is Outcome.SUCCESS
                for attempt_id in attempt_ids
            )
            for attempt_ids in run.logical_attempts.values()
        ):
            state, reason = DecisionState.DENY, "incomplete-logical-work"
        else:
            run.state = RunState.COMPLETE
        receipt = self._receipt(
            stage="completion",
            state=state,
            reason=reason,
            run_id=run_id,
            tenant=run.root.tenant if run else "",
            component="supervisor",
            step=step,
            run=run,
        )
        return ControlDecision(state, reason, receipt)


def build_scenario() -> tuple[CascadeController, dict[str, WorkloadIdentity]]:
    identities = {
        "supervisor": WorkloadIdentity(
            "supervisor", "north", "spiffe://example.test/agent/supervisor"
        ),
        "research": WorkloadIdentity(
            "research", "north", "spiffe://example.test/agent/research"
        ),
        "billing": WorkloadIdentity(
            "billing", "north", "spiffe://example.test/agent/billing"
        ),
        "messaging": WorkloadIdentity(
            "messaging", "north", "spiffe://example.test/agent/messaging"
        ),
        "ticket": WorkloadIdentity(
            "ticket", "north", "spiffe://example.test/agent/ticket"
        ),
    }
    supervisor = identities["supervisor"]
    policy = CascadePolicy(
        version="cascade-policy-3",
        identities=frozenset(
            (identity.subject, identity.workload_id)
            for identity in identities.values()
        ),
        allowed_edges=frozenset(
            (supervisor.workload_id, identity.workload_id)
            for name, identity in identities.items()
            if name != "supervisor"
        ),
        task_types={
            "research": frozenset({"gather-evidence"}),
            "billing": frozenset({"check-account"}),
            "messaging": frozenset({"draft-message"}),
            "ticket": frozenset({"draft-ticket"}),
        },
        effect_permissions={
            "research": frozenset(),
            "billing": frozenset(),
            "messaging": frozenset({"draft-customer-message"}),
            "ticket": frozenset({"create-internal-ticket"}),
        },
    )
    return CascadeController(policy), identities


def root_task(*, run_id: str = "run:42", tenant: str = "north") -> RootTask:
    return RootTask(
        run_id=run_id,
        task_id="support:case:42",
        tenant=tenant,
        task_type="support-triage",
        payload_digest=_digest("case 42 bounded support request"),
    )


def start_run(
    controller: CascadeController,
    identities: Mapping[str, WorkloadIdentity],
    *,
    run_id: str = "run:42",
    step: int = 0,
) -> RunRecord:
    decision = controller.start(
        identities["supervisor"], root_task(run_id=run_id), step=step
    )
    assert decision.allowed
    return controller.runs[run_id]


def dispatch_for(
    run: RunRecord,
    identities: Mapping[str, WorkloadIdentity],
    target: str,
    *,
    attempt_id: str,
    logical_id: str | None = None,
    depth: int = 1,
    retry_of: str | None = None,
) -> DispatchProposal:
    task_types = {
        "research": "gather-evidence",
        "billing": "check-account",
        "messaging": "draft-message",
        "ticket": "draft-ticket",
    }
    return DispatchProposal(
        attempt_id=attempt_id,
        logical_id=logical_id or f"logical:{target}",
        parent_attempt_id=run.root.task_id,
        target=target,
        target_workload_id=identities[target].workload_id,
        tenant=run.root.tenant,
        task_type=task_types[target],
        depth=depth,
        payload_digest=run.root.payload_digest,
        retry_of=retry_of,
    )


def observation_for(
    attempt: QueuedAttempt,
    identity: WorkloadIdentity,
    outcome: Outcome,
) -> ExecutionObservation:
    return ExecutionObservation(
        attempt_id=attempt.proposal.attempt_id,
        component=identity.subject,
        component_workload_id=identity.workload_id,
        tenant=identity.tenant,
        outcome=outcome,
        result_digest=_digest(
            {
                "attempt": attempt.proposal.attempt_id,
                "outcome": outcome.value,
            }
        ),
    )


def dispatch_and_observe(
    controller: CascadeController,
    identities: Mapping[str, WorkloadIdentity],
    run: RunRecord,
    target: str,
    *,
    attempt_id: str,
    outcome: Outcome,
    step: int,
    logical_id: str | None = None,
    retry_of: str | None = None,
) -> tuple[ControlDecision, ControlDecision]:
    proposal = dispatch_for(
        run,
        identities,
        target,
        attempt_id=attempt_id,
        logical_id=logical_id,
        retry_of=retry_of,
    )
    dispatched = controller.dispatch(
        identities["supervisor"], run.root.run_id, proposal, step=step
    )
    assert dispatched.allowed and dispatched.attempt
    observed = controller.observe(
        identities[target],
        run.root.run_id,
        observation_for(dispatched.attempt, identities[target], outcome),
        step=step + 1,
    )
    return dispatched, observed


def unsafe_naive_cascade(
    *, retries_per_layer: int = 3, retrying_layers: int = 3
) -> CascadeComparison:
    """Deliberately unsafe comparison: each layer retries independently."""

    attempts = (retries_per_layer + 1) ** retrying_layers
    return CascadeComparison(
        unsafe_attempts=attempts,
        unsafe_affected_components=4,
        unsafe_unauthorized_effects=2,
        unsafe_stop_latency_steps=8,
        controlled_attempts=1,
        controlled_affected_components=1,
        controlled_unauthorized_effects=0,
        controlled_stop_latency_steps=0,
    )


def controlled_poison_cascade() -> tuple[
    CascadeController,
    RunRecord,
    ControlDecision,
]:
    controller, identities = build_scenario()
    run = start_run(controller, identities)
    _, contained = dispatch_and_observe(
        controller,
        identities,
        run,
        "research",
        attempt_id="attempt:research:1",
        outcome=Outcome.POISONED,
        step=1,
    )
    assert contained.state is DecisionState.STOP
    return controller, run, contained


def evaluate_controls() -> tuple[EvaluationReport, tuple[ControlCase, ...]]:
    cases: list[ControlCase] = []
    affected_counts: list[int] = []
    stop_latencies: list[int] = []

    def add(
        name: str,
        population: str,
        family: str,
        decision: ControlDecision,
        *,
        safe: bool,
        forbidden_effect: bool = False,
    ) -> None:
        receipt = decision.receipt
        cases.append(
            ControlCase(
                name,
                population,
                family,
                decision.state,
                safe,
                forbidden_effect,
                bool(
                    receipt.receipt_id
                    and receipt.stage
                    and receipt.reason
                    and receipt.run_id
                    and receipt.policy_version
                    and receipt.step >= 0
                ),
            )
        )
        affected_counts.append(receipt.affected_components)

    # Five valid workflows.
    controller, identities = build_scenario()
    run = start_run(controller, identities)
    for index, target in enumerate(("research", "billing", "ticket"), start=1):
        dispatch_and_observe(
            controller,
            identities,
            run,
            target,
            attempt_id=f"attempt:{target}:1",
            outcome=Outcome.SUCCESS,
            step=index * 2 - 1,
        )
    completed = controller.complete(run.root.run_id, step=8)
    add(
        "valid-bounded-fanout",
        "valid",
        "workflow",
        completed,
        safe=completed.allowed and len(run.affected_components) == 3,
    )

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    proposal = dispatch_for(
        run, identities, "research", attempt_id="attempt:idempotent"
    )
    first = controller.dispatch(
        identities["supervisor"], run.root.run_id, proposal, step=1
    )
    second = controller.dispatch(
        identities["supervisor"], run.root.run_id, proposal, step=2
    )
    add(
        "valid-idempotent-dispatch",
        "valid",
        "replay",
        second,
        safe=first.allowed and second.allowed and second.replayed,
    )

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    first, _ = dispatch_and_observe(
        controller,
        identities,
        run,
        "billing",
        attempt_id="attempt:billing:1",
        logical_id="logical:billing-retry",
        outcome=Outcome.TRANSIENT_FAILURE,
        step=1,
    )
    retry, observed = dispatch_and_observe(
        controller,
        identities,
        run,
        "billing",
        attempt_id="attempt:billing:2",
        logical_id="logical:billing-retry",
        retry_of=first.attempt.proposal.attempt_id,
        outcome=Outcome.SUCCESS,
        step=3,
    )
    add(
        "valid-centralized-retry",
        "valid",
        "retry",
        observed,
        safe=retry.allowed and run.retry_budget_used == 1,
    )

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    for index in (1, 2):
        dispatch_and_observe(
            controller,
            identities,
            run,
            "billing",
            attempt_id=f"attempt:breaker:{index}",
            logical_id=f"logical:breaker:{index}",
            outcome=Outcome.TRANSIENT_FAILURE,
            step=index * 2 - 1,
        )
    research, _ = dispatch_and_observe(
        controller,
        identities,
        run,
        "research",
        attempt_id="attempt:isolated:research",
        outcome=Outcome.SUCCESS,
        step=5,
    )
    add(
        "valid-circuit-isolates-one-component",
        "valid",
        "circuit",
        research,
        safe=research.allowed
        and run.circuits["billing"].state is BreakerState.OPEN,
    )

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    dispatched, _ = dispatch_and_observe(
        controller,
        identities,
        run,
        "ticket",
        attempt_id="attempt:ticket:1",
        outcome=Outcome.SUCCESS,
        step=1,
    )
    effect_proposal = EffectProposal(
        "operation:ticket:42",
        "create-internal-ticket",
        "case:north:42",
        dispatched.attempt.proposal.attempt_id,
    )
    first_effect = controller.authorize_effect(
        identities["ticket"], run.root.run_id, effect_proposal, step=3
    )
    replay = controller.authorize_effect(
        identities["ticket"], run.root.run_id, effect_proposal, step=4
    )
    add(
        "valid-idempotent-effect",
        "valid",
        "effect",
        replay,
        safe=first_effect.allowed and replay.allowed and replay.replayed and len(run.effects) == 1,
    )

    # Twelve attack and amplification cases.
    controller, identities = build_scenario()
    denied = controller.start(
        replace(identities["supervisor"], authenticated=False), root_task(), step=0
    )
    add("unauthenticated-coordinator", "attack", "identity", denied, safe=not denied.allowed)

    controller, identities = build_scenario()
    denied = controller.start(
        identities["supervisor"], root_task(tenant="south"), step=0
    )
    add("cross-tenant-run", "attack", "tenant", denied, safe=not denied.allowed)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    recursive = controller.dispatch(
        identities["research"],
        run.root.run_id,
        dispatch_for(run, identities, "billing", attempt_id="attempt:recursive"),
        step=1,
    )
    add("recursive-delegation", "attack", "edge", recursive, safe=not recursive.allowed)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    too_deep = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        dispatch_for(
            run, identities, "research", attempt_id="attempt:deep", depth=2
        ),
        step=1,
    )
    add("depth-amplification", "attack", "budget", too_deep, safe=not too_deep.allowed)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    for index, target in enumerate(("research", "billing", "ticket"), start=1):
        dispatch_and_observe(
            controller,
            identities,
            run,
            target,
            attempt_id=f"attempt:fanout:{index}",
            logical_id=f"logical:fanout:{index}",
            outcome=Outcome.SUCCESS,
            step=index * 2 - 1,
        )
    fourth = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        dispatch_for(
            run,
            identities,
            "messaging",
            attempt_id="attempt:fanout:4",
            logical_id="logical:fanout:4",
        ),
        step=7,
    )
    add("fanout-amplification", "attack", "budget", fourth, safe=not fourth.allowed)

    controller, identities = build_scenario()
    controller.policy = replace(
        controller.policy,
        max_dispatches=3,
        max_retries_per_logical=5,
        retry_budget=5,
        breaker_threshold=10,
    )
    run = start_run(controller, identities)
    previous: str | None = None
    for index in range(1, 4):
        dispatched, _ = dispatch_and_observe(
            controller,
            identities,
            run,
            "billing",
            attempt_id=f"attempt:global:{index}",
            logical_id="logical:global-budget",
            retry_of=previous,
            outcome=Outcome.TRANSIENT_FAILURE,
            step=index * 2 - 1,
        )
        previous = dispatched.attempt.proposal.attempt_id
    exhausted = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        dispatch_for(
            run,
            identities,
            "billing",
            attempt_id="attempt:global:4",
            logical_id="logical:global-budget",
            retry_of=previous,
        ),
        step=7,
    )
    add("dispatch-amplification", "attack", "budget", exhausted, safe=not exhausted.allowed)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    for index in (1, 2):
        proposal = dispatch_for(
            run,
            identities,
            "research",
            attempt_id=f"attempt:queue:{index}",
            logical_id=f"logical:queue:{index}",
        )
        assert controller.dispatch(
            identities["supervisor"], run.root.run_id, proposal, step=index
        ).allowed
    queue_full = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        dispatch_for(
            run,
            identities,
            "research",
            attempt_id="attempt:queue:3",
            logical_id="logical:queue:3",
        ),
        step=3,
    )
    add("queue-amplification", "attack", "bulkhead", queue_full, safe=not queue_full.allowed)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    proposal = dispatch_for(
        run, identities, "research", attempt_id="attempt:mutation"
    )
    assert controller.dispatch(
        identities["supervisor"], run.root.run_id, proposal, step=1
    ).allowed
    mutation = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        replace(proposal, task_type="check-account"),
        step=2,
    )
    add("mutated-redelivery", "attack", "replay", mutation, safe=not mutation.allowed)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    dispatched, _ = dispatch_and_observe(
        controller,
        identities,
        run,
        "billing",
        attempt_id="attempt:permanent:1",
        logical_id="logical:permanent",
        outcome=Outcome.PERMANENT_FAILURE,
        step=1,
    )
    permanent_retry = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        dispatch_for(
            run,
            identities,
            "billing",
            attempt_id="attempt:permanent:2",
            logical_id="logical:permanent",
            retry_of=dispatched.attempt.proposal.attempt_id,
        ),
        step=3,
    )
    add("permanent-error-retry", "attack", "retry", permanent_retry, safe=not permanent_retry.allowed)

    controller, identities = build_scenario()
    controller.policy = replace(controller.policy, breaker_threshold=10)
    run = start_run(controller, identities)
    first_attempts: list[ControlDecision] = []
    for index, target in enumerate(("research", "billing", "ticket"), start=1):
        dispatched, _ = dispatch_and_observe(
            controller,
            identities,
            run,
            target,
            attempt_id=f"attempt:retry-budget:{index}:1",
            logical_id=f"logical:retry-budget:{index}",
            outcome=Outcome.TRANSIENT_FAILURE,
            step=index * 2 - 1,
        )
        first_attempts.append(dispatched)
    for index in (0, 1):
        dispatch_and_observe(
            controller,
            identities,
            run,
            ("research", "billing")[index],
            attempt_id=f"attempt:retry-budget:{index + 1}:2",
            logical_id=f"logical:retry-budget:{index + 1}",
            retry_of=first_attempts[index].attempt.proposal.attempt_id,
            outcome=Outcome.TRANSIENT_FAILURE,
            step=7 + index * 2,
        )
    retry_exhausted = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        dispatch_for(
            run,
            identities,
            "ticket",
            attempt_id="attempt:retry-budget:3:2",
            logical_id="logical:retry-budget:3",
            retry_of=first_attempts[2].attempt.proposal.attempt_id,
        ),
        step=11,
    )
    add("run-retry-amplification", "attack", "retry", retry_exhausted, safe=not retry_exhausted.allowed)

    controller, run, contained = controlled_poison_cascade()
    stop_latencies.append(run.stop_latency_steps or 0)
    add(
        "poisoned-result-containment",
        "attack",
        "poison",
        contained,
        safe=run.state is RunState.CONTAINED and not run.effects,
        forbidden_effect=bool(run.effects),
    )

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    dispatched, _ = dispatch_and_observe(
        controller,
        identities,
        run,
        "research",
        attempt_id="attempt:authority:1",
        outcome=Outcome.SUCCESS,
        step=1,
    )
    unauthorized = controller.authorize_effect(
        identities["research"],
        run.root.run_id,
        EffectProposal(
            "operation:message-demand",
            "send-customer-message",
            "case:north:42",
            dispatched.attempt.proposal.attempt_id,
        ),
        step=3,
    )
    add(
        "result-text-as-authority",
        "attack",
        "effect",
        unauthorized,
        safe=not unauthorized.allowed and not run.effects,
        forbidden_effect=bool(run.effects),
    )

    # Three dependency failures stay ERROR, not apparent successful defenses.
    controller, identities = build_scenario()
    controller.policy_available = False
    failed = controller.start(identities["supervisor"], root_task(), step=0)
    add("policy-unavailable", "failure", "dependency", failed, safe=failed.state is DecisionState.ERROR)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    controller.ledger_available = False
    failed = controller.dispatch(
        identities["supervisor"],
        run.root.run_id,
        dispatch_for(run, identities, "research", attempt_id="attempt:ledger"),
        step=1,
    )
    add("ledger-unavailable", "failure", "dependency", failed, safe=failed.state is DecisionState.ERROR)

    controller, identities = build_scenario()
    run = start_run(controller, identities)
    dispatched, _ = dispatch_and_observe(
        controller,
        identities,
        run,
        "ticket",
        attempt_id="attempt:executor",
        outcome=Outcome.SUCCESS,
        step=1,
    )
    controller.effect_executor_available = False
    failed = controller.authorize_effect(
        identities["ticket"],
        run.root.run_id,
        EffectProposal(
            "operation:executor",
            "create-internal-ticket",
            "case:north:42",
            dispatched.attempt.proposal.attempt_id,
        ),
        step=3,
    )
    add("effect-executor-unavailable", "failure", "dependency", failed, safe=failed.state is DecisionState.ERROR and not run.effects)

    valid_cases = [case for case in cases if case.population == "valid"]
    attack_cases = [case for case in cases if case.population == "attack"]
    failure_cases = [case for case in cases if case.population == "failure"]
    comparison = unsafe_naive_cascade()
    report = EvaluationReport(
        total_cases=len(cases),
        valid_cases=len(valid_cases),
        attack_cases=len(attack_cases),
        failure_cases=len(failure_cases),
        valid_completion_rate=sum(case.safe for case in valid_cases) / len(valid_cases),
        attack_forbidden_effect_rate=sum(
            case.forbidden_effect for case in attack_cases
        )
        / len(attack_cases),
        failure_error_rate=sum(
            case.state is DecisionState.ERROR for case in failure_cases
        )
        / len(failure_cases),
        max_affected_components=max(affected_counts),
        max_stop_latency_steps=max(stop_latencies or [0]),
        controlled_retry_amplification=2.0,
        unsafe_retry_amplification=float(comparison.unsafe_attempts),
        trace_completeness_rate=sum(case.trace_complete for case in cases) / len(cases),
    )
    return report, tuple(cases)


def demo() -> None:
    report, cases = evaluate_controls()
    assert (
        report.total_cases,
        report.valid_cases,
        report.attack_cases,
        report.failure_cases,
    ) == (20, 5, 12, 3)
    assert report.valid_completion_rate == 1.0
    assert report.attack_forbidden_effect_rate == 0.0
    assert report.failure_error_rate == 1.0
    assert report.max_affected_components <= 3
    assert report.max_stop_latency_steps == 0
    assert report.trace_completeness_rate == 1.0
    print(asdict(report))
    for case in cases:
        print(asdict(case))


if __name__ == "__main__":
    demo()
