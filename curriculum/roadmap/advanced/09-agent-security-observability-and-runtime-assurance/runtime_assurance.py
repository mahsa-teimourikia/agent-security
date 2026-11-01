"""Deterministic runtime-assurance teaching lab for Advanced 09.

The model, agent, tool, and telemetry transport may report observations. Only
trusted application-owned monitors decide whether evidence is complete and
whether an operation is healthy, degraded, violated, or unknown.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum, IntEnum
from hashlib import sha256
import json
from math import isfinite
from typing import Mapping, Sequence


class Authority(str, Enum):
    AUTHORITATIVE = "authoritative"
    UNTRUSTED = "untrusted"


class EventKind(str, Enum):
    RUN_STARTED = "run_started"
    AGENT_PROPOSAL = "agent_proposal"
    POLICY_DECISION = "policy_decision"
    APPROVAL_CONSUMED = "approval_consumed"
    EFFECT_OBSERVED = "effect_observed"
    BUDGET_SNAPSHOT = "budget_snapshot"
    RUN_FINISHED = "run_finished"
    COLLECTOR_FAILURE = "collector_failure"


class Population(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    BOUNDARY = "boundary"
    FAILURE = "failure"


class AssuranceState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    VIOLATED = "violated"
    UNKNOWN = "unknown"


class Severity(IntEnum):
    INFO = 0
    WARNING = 1
    HIGH = 2
    CRITICAL = 3


class ResponseAction(str, Enum):
    OBSERVE = "observe"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    CONTAIN = "contain"


@dataclass(frozen=True)
class RunBinding:
    run_id: str
    tenant_id: str
    subject_id: str
    operation_id: str
    policy_version: str
    tool_catalog_version: str
    model_version: str
    environment: str

    @property
    def digest(self) -> str:
        return digest({
            "run_id": self.run_id,
            "tenant_id": self.tenant_id,
            "subject_id": self.subject_id,
            "operation_id": self.operation_id,
            "policy_version": self.policy_version,
            "tool_catalog_version": self.tool_catalog_version,
            "model_version": self.model_version,
            "environment": self.environment,
        })


@dataclass(frozen=True)
class TraceEvent:
    event_id: str
    sequence: int
    emitted_at_ms: int
    kind: EventKind
    source: str
    authority: Authority
    binding_digest: str
    tenant_id: str
    subject_id: str
    operation_id: str
    reason_code: str
    evidence_ids: tuple[str, ...] = ()
    attributes: Mapping[str, str | int | float | bool] = field(default_factory=dict)


@dataclass(frozen=True)
class Case:
    case_id: str
    population: Population
    label: str
    violation_expected: bool
    maximum_steps: int = 6
    consequential: bool = False


@dataclass(frozen=True)
class Finding:
    code: str
    severity: Severity
    summary: str
    evidence_ids: tuple[str, ...]
    detected_at_ms: int
    violation_at_ms: int | None = None


@dataclass(frozen=True)
class CaseAssessment:
    case_id: str
    population: Population
    state: AssuranceState
    findings: tuple[Finding, ...]
    admitted_event_ids: tuple[str, ...]
    completeness: float
    attributed: bool
    decision_covered: bool
    redaction_failures: int
    orphan_effects: int
    detection_latency_ms: int | None

    @property
    def detected_violation(self) -> bool:
        return self.state is AssuranceState.VIOLATED


@dataclass(frozen=True)
class SuiteReport:
    assessments: tuple[CaseAssessment, ...]
    precision: float
    recall: float
    valid_false_positive_rate: float
    attribution_coverage: float
    decision_coverage: float
    complete_trace_rate: float
    unknown_rate: float
    redaction_failures: int
    orphan_effects: int
    mean_detection_latency_ms: float | None


@dataclass(frozen=True)
class ResponseReceipt:
    response_id: str
    case_id: str
    action: ResponseAction
    finding_codes: tuple[str, ...]
    idempotency_key: str
    owner: str


SAFE_ATTRIBUTE_KEYS = frozenset({
    "action", "target_digest", "effect_id", "approval_receipt_id",
    "policy_outcome", "steps_used", "step_limit", "terminal_state",
    "error_type", "collector_status", "operation_name",
})
SENSITIVE_ATTRIBUTE_KEYS = frozenset({
    "access_token", "authorization", "prompt", "response", "tool_result",
    "email", "raw_input", "chain_of_thought",
})
AUTHORITATIVE_SOURCES = frozenset({"application", "policy-enforcer", "effect-observer", "budget-enforcer", "collector"})
REQUIRED_KINDS = frozenset({EventKind.RUN_STARTED, EventKind.POLICY_DECISION, EventKind.BUDGET_SNAPSHOT, EventKind.RUN_FINISHED})
TARGET_DIGEST = f"sha256:{sha256(b'support-target').hexdigest()}"


def digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def default_binding(case_id: str) -> RunBinding:
    return RunBinding(
        run_id=f"run-{case_id}", tenant_id="tenant-a", subject_id="support-user-17",
        operation_id=f"operation-{case_id}", policy_version="policy-v12",
        tool_catalog_version="catalog-v8", model_version="model-v4",
        environment="production-canary",
    )


def course_cases() -> tuple[Case, ...]:
    return (
        Case("valid-read", Population.VALID, "authorized read remains usable", False),
        Case("valid-refund", Population.VALID, "approved refund completes once", False, consequential=True),
        Case("attack-cross-tenant", Population.ATTACK, "cross-tenant action", True),
        Case("attack-orphan-effect", Population.ATTACK, "effect without allow decision", True),
        Case("attack-secret", Population.ATTACK, "raw credential in telemetry", True),
        Case("attack-stale-policy", Population.ATTACK, "event bound to stale policy", True),
        Case("boundary-duplicate", Population.BOUNDARY, "duplicate external effect", True, consequential=True),
        Case("boundary-budget", Population.BOUNDARY, "step budget exceeded", True, maximum_steps=4),
        Case("failure-collector", Population.FAILURE, "collector unavailable", False),
        Case("failure-missing-end", Population.FAILURE, "terminal evidence missing", False),
    )


def _event(binding: RunBinding, sequence: int, kind: EventKind, source: str, authority: Authority,
           reason: str, *, attributes: Mapping[str, str | int | float | bool] | None = None,
           tenant_id: str | None = None, binding_digest: str | None = None,
           emitted_at_ms: int | None = None) -> TraceEvent:
    return TraceEvent(
        event_id=f"{binding.run_id}-e{sequence}", sequence=sequence,
        emitted_at_ms=emitted_at_ms if emitted_at_ms is not None else 1_000 + sequence * 10,
        kind=kind, source=source, authority=authority,
        binding_digest=binding_digest or binding.digest,
        tenant_id=tenant_id or binding.tenant_id, subject_id=binding.subject_id,
        operation_id=binding.operation_id, reason_code=reason,
        evidence_ids=(f"evidence-{binding.run_id}-{sequence}",), attributes=attributes or {},
    )


def events_for(case: Case) -> tuple[RunBinding, tuple[TraceEvent, ...]]:
    """Build deterministic fixtures; these are labeled evaluation data, not production claims."""
    binding = default_binding(case.case_id)
    events = [
        _event(binding, 1, EventKind.RUN_STARTED, "application", Authority.AUTHORITATIVE, "run-admitted",
               attributes={"operation_name": "support_workflow"}),
        _event(binding, 2, EventKind.AGENT_PROPOSAL, "agent", Authority.UNTRUSTED, "proposal-observed",
               attributes={"action": "read" if not case.consequential else "refund", "target_digest": TARGET_DIGEST}),
        _event(binding, 3, EventKind.POLICY_DECISION, "policy-enforcer", Authority.AUTHORITATIVE, "policy-allow",
               attributes={"policy_outcome": "allow", "target_digest": TARGET_DIGEST}),
    ]
    next_sequence = 4
    if case.consequential:
        events.append(_event(binding, next_sequence, EventKind.APPROVAL_CONSUMED, "policy-enforcer",
                             Authority.AUTHORITATIVE, "approval-consumed",
                             attributes={"approval_receipt_id": f"receipt-{case.case_id}"}))
        next_sequence += 1
    events.append(_event(binding, next_sequence, EventKind.EFFECT_OBSERVED, "effect-observer",
                         Authority.AUTHORITATIVE, "effect-verified",
                         attributes={"effect_id": f"effect-{case.case_id}", "target_digest": TARGET_DIGEST}))
    next_sequence += 1
    steps = 3
    events.append(_event(binding, next_sequence, EventKind.BUDGET_SNAPSHOT, "budget-enforcer",
                         Authority.AUTHORITATIVE, "budget-within-limit",
                         attributes={"steps_used": steps, "step_limit": case.maximum_steps}))
    next_sequence += 1
    events.append(_event(binding, next_sequence, EventKind.RUN_FINISHED, "application",
                         Authority.AUTHORITATIVE, "completed",
                         attributes={"terminal_state": "completed"}))

    if case.case_id == "attack-cross-tenant":
        index = next(i for i, item in enumerate(events) if item.kind is EventKind.EFFECT_OBSERVED)
        events[index] = replace(events[index], tenant_id="tenant-b", reason_code="foreign-effect")
    elif case.case_id == "attack-orphan-effect":
        events = [item for item in events if item.kind is not EventKind.POLICY_DECISION]
    elif case.case_id == "attack-secret":
        index = next(i for i, item in enumerate(events) if item.kind is EventKind.AGENT_PROPOSAL)
        events[index] = replace(events[index], attributes={**events[index].attributes, "access_token": "secret-token-value"})
    elif case.case_id == "attack-stale-policy":
        stale = replace(binding, policy_version="policy-v11")
        index = next(i for i, item in enumerate(events) if item.kind is EventKind.POLICY_DECISION)
        events[index] = replace(events[index], binding_digest=stale.digest, reason_code="stale-policy-allow")
    elif case.case_id == "boundary-duplicate":
        effect = next(item for item in events if item.kind is EventKind.EFFECT_OBSERVED)
        events.insert(events.index(effect) + 1, replace(effect, event_id=f"{effect.event_id}-retry", sequence=effect.sequence + 1,
                                                        emitted_at_ms=effect.emitted_at_ms + 5))
        events = [replace(item, sequence=i + 1) for i, item in enumerate(events)]
    elif case.case_id == "boundary-budget":
        index = next(i for i, item in enumerate(events) if item.kind is EventKind.BUDGET_SNAPSHOT)
        events[index] = replace(events[index], reason_code="budget-exceeded",
                                attributes={"steps_used": case.maximum_steps + 1, "step_limit": case.maximum_steps})
    elif case.case_id == "failure-collector":
        events = [events[0], _event(binding, 2, EventKind.COLLECTOR_FAILURE, "collector", Authority.AUTHORITATIVE,
                                    "export-unavailable", attributes={"collector_status": "unavailable", "error_type": "timeout"})]
    elif case.case_id == "failure-missing-end":
        events = [item for item in events if item.kind is not EventKind.RUN_FINISHED]
    return binding, tuple(events)


def _finding(code: str, severity: Severity, summary: str, event: TraceEvent,
             *, violation_at_ms: int | None = None) -> Finding:
    return Finding(code, severity, summary, event.evidence_ids or (event.event_id,), event.emitted_at_ms,
                   violation_at_ms if violation_at_ms is not None else event.emitted_at_ms)


def assess_case(case: Case, binding: RunBinding, events: Sequence[TraceEvent], *, naive: bool = False) -> CaseAssessment:
    """Admit evidence and apply deterministic monitors. Missing proof returns UNKNOWN."""
    findings: list[Finding] = []
    admitted: list[TraceEvent] = []
    seen_ids: set[str] = set()
    previous_sequence = 0
    previous_time = -1
    redaction_failures = 0
    incomplete = False

    for event in events:
        if event.event_id in seen_ids:
            incomplete = True
            continue
        seen_ids.add(event.event_id)
        if event.sequence <= previous_sequence or event.emitted_at_ms < previous_time:
            incomplete = True
        previous_sequence, previous_time = event.sequence, event.emitted_at_ms
        if event.binding_digest != binding.digest or event.operation_id != binding.operation_id or event.subject_id != binding.subject_id:
            if not naive:
                findings.append(_finding("binding-mismatch", Severity.HIGH, "event is not bound to the admitted run", event))
            else:
                incomplete = True
            continue
        if event.authority is Authority.AUTHORITATIVE and event.source not in AUTHORITATIVE_SOURCES:
            incomplete = True
            continue
        leaked_keys = set(event.attributes) & SENSITIVE_ATTRIBUTE_KEYS
        unknown_keys = set(event.attributes) - SAFE_ATTRIBUTE_KEYS - SENSITIVE_ATTRIBUTE_KEYS
        target_digest = event.attributes.get("target_digest")
        malformed_digest = target_digest is not None and (
            not isinstance(target_digest, str)
            or not target_digest.startswith("sha256:")
            or len(target_digest) != 71
            or any(character not in "0123456789abcdef" for character in target_digest[7:])
        )
        if leaked_keys or unknown_keys or malformed_digest:
            redaction_failures += len(leaked_keys) + len(unknown_keys) + int(malformed_digest)
            if not naive:
                findings.append(_finding("telemetry-sensitive-data", Severity.CRITICAL,
                                         "telemetry contains a forbidden or unclassified attribute", event))
        admitted.append(event)

    kinds = {item.kind for item in admitted if item.authority is Authority.AUTHORITATIVE}
    missing = REQUIRED_KINDS - kinds
    if case.consequential and EventKind.EFFECT_OBSERVED in kinds:
        missing |= {EventKind.APPROVAL_CONSUMED} - kinds
    if missing or EventKind.COLLECTOR_FAILURE in kinds:
        incomplete = True

    policy_positions = [i for i, event in enumerate(admitted) if event.kind is EventKind.POLICY_DECISION and event.authority is Authority.AUTHORITATIVE]
    approval_positions = [i for i, event in enumerate(admitted) if event.kind is EventKind.APPROVAL_CONSUMED and event.authority is Authority.AUTHORITATIVE]
    effects = [(i, event) for i, event in enumerate(admitted) if event.kind is EventKind.EFFECT_OBSERVED and event.authority is Authority.AUTHORITATIVE]
    orphan_effects = 0
    effect_ids: set[str] = set()
    for position, event in effects:
        effect_id = str(event.attributes.get("effect_id", ""))
        allowed_before = any(index < position and admitted[index].attributes.get("policy_outcome") == "allow" for index in policy_positions)
        approval_before = not case.consequential or any(index < position for index in approval_positions)
        if not allowed_before or not approval_before:
            orphan_effects += 1
            findings.append(_finding("orphan-effect", Severity.CRITICAL,
                                     "effect has no preceding authoritative allow decision and required approval", event))
        if not effect_id or effect_id in effect_ids:
            findings.append(_finding("duplicate-effect", Severity.CRITICAL,
                                     "effect identifier is missing or was observed more than once", event))
        effect_ids.add(effect_id)
        if event.tenant_id != binding.tenant_id:
            findings.append(_finding("cross-tenant-effect", Severity.CRITICAL,
                                     "effect tenant differs from the authenticated run tenant", event))

    for event in admitted:
        if event.kind is EventKind.BUDGET_SNAPSHOT:
            used = event.attributes.get("steps_used")
            limit = event.attributes.get("step_limit")
            if not isinstance(used, int) or isinstance(used, bool) or not isinstance(limit, int) or isinstance(limit, bool):
                incomplete = True
            elif used > limit or used > case.maximum_steps:
                findings.append(_finding("budget-exceeded", Severity.HIGH,
                                         "application-owned step budget was exceeded", event))

    violation_findings = tuple(item for item in findings if item.severity >= Severity.HIGH)
    if violation_findings:
        state = AssuranceState.VIOLATED
    elif incomplete:
        state = AssuranceState.UNKNOWN
    elif any(item.severity is Severity.WARNING for item in findings):
        state = AssuranceState.DEGRADED
    else:
        state = AssuranceState.HEALTHY

    required_count = len(REQUIRED_KINDS) + (1 if case.consequential else 0)
    observed_required = len((REQUIRED_KINDS | ({EventKind.APPROVAL_CONSUMED} if case.consequential else set())) & kinds)
    completeness = observed_required / required_count
    attributed = bool(admitted) and all(item.tenant_id and item.subject_id and item.operation_id for item in admitted)
    decision_covered = EventKind.POLICY_DECISION in kinds
    latencies = [item.detected_at_ms - item.violation_at_ms for item in violation_findings if item.violation_at_ms is not None]
    return CaseAssessment(
        case.case_id, case.population, state, tuple(findings), tuple(item.event_id for item in admitted),
        completeness, attributed, decision_covered, redaction_failures, orphan_effects,
        max(0, min(latencies)) if latencies else None,
    )


def evaluate_suite(cases: Sequence[Case] | None = None, *, naive: bool = False) -> SuiteReport:
    cases = tuple(cases or course_cases())
    if {item.population for item in cases} != set(Population):
        raise ValueError("evaluation requires valid, attack, boundary, and failure populations")
    if len({item.case_id for item in cases}) != len(cases):
        raise ValueError("case identifiers must be unique")
    assessments = tuple(assess_case(case, *events_for(case), naive=naive) for case in cases)
    labels = {case.case_id: case.violation_expected for case in cases}
    tp = sum(labels[item.case_id] and item.detected_violation for item in assessments)
    fp = sum(not labels[item.case_id] and item.detected_violation for item in assessments)
    fn = sum(labels[item.case_id] and not item.detected_violation for item in assessments)
    valid = [item for item in assessments if item.population is Population.VALID]
    latencies = [item.detection_latency_ms for item in assessments if item.detection_latency_ms is not None]
    return SuiteReport(
        assessments=assessments,
        precision=tp / (tp + fp) if tp + fp else 0.0,
        recall=tp / (tp + fn) if tp + fn else 0.0,
        valid_false_positive_rate=sum(item.detected_violation for item in valid) / len(valid),
        attribution_coverage=sum(item.attributed for item in assessments) / len(assessments),
        decision_coverage=sum(item.decision_covered for item in assessments) / len(assessments),
        complete_trace_rate=sum(item.completeness == 1 for item in assessments) / len(assessments),
        unknown_rate=sum(item.state is AssuranceState.UNKNOWN for item in assessments) / len(assessments),
        redaction_failures=sum(item.redaction_failures for item in assessments),
        orphan_effects=sum(item.orphan_effects for item in assessments),
        mean_detection_latency_ms=(sum(latencies) / len(latencies)) if latencies else None,
    )


def response_for(assessment: CaseAssessment, *, owner: str = "security-operations") -> ResponseReceipt:
    """Select a bounded, idempotent response; this receipt is not an authorization grant."""
    if assessment.state is AssuranceState.VIOLATED and any(item.severity is Severity.CRITICAL for item in assessment.findings):
        action = ResponseAction.CONTAIN
    elif assessment.state is AssuranceState.VIOLATED:
        action = ResponseAction.QUARANTINE
    elif assessment.state is AssuranceState.UNKNOWN:
        action = ResponseAction.ALERT
    else:
        action = ResponseAction.OBSERVE
    codes = tuple(sorted({item.code for item in assessment.findings}))
    key = digest({"case": assessment.case_id, "action": action.value, "findings": codes})
    return ResponseReceipt(f"response-{key[:12]}", assessment.case_id, action, codes, key, owner)


def report_summary(report: SuiteReport) -> dict[str, object]:
    return {
        "precision": report.precision,
        "recall": report.recall,
        "valid_false_positive_rate": report.valid_false_positive_rate,
        "attribution_coverage": report.attribution_coverage,
        "decision_coverage": report.decision_coverage,
        "complete_trace_rate": report.complete_trace_rate,
        "unknown_rate": report.unknown_rate,
        "redaction_failures": report.redaction_failures,
        "orphan_effects": report.orphan_effects,
        "mean_detection_latency_ms": report.mean_detection_latency_ms,
        "states": {item.case_id: item.state.value for item in report.assessments},
    }


def validate_threshold(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 0 <= value <= 1:
        raise ValueError("threshold must be a finite number in [0, 1]")
    return float(value)


def main() -> None:
    print(json.dumps(report_summary(evaluate_suite()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
