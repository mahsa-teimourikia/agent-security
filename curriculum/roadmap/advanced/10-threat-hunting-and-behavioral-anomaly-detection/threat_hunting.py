"""Deterministic, evidence-linked threat-hunting lab for Advanced 10.

The detector creates hypotheses from admitted telemetry. It never authorizes a
response, invents missing evidence, or treats an anomaly score as a verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum, IntEnum
import json
from math import isfinite
from typing import Mapping, Sequence
from urllib.parse import urlsplit


class Population(str, Enum):
    VALID = "valid"
    ATTACK = "attack"
    BOUNDARY = "boundary"
    FAILURE = "failure"


class EventKind(str, Enum):
    RETRIEVAL = "retrieval"
    DELEGATION = "delegation"
    APPROVAL = "approval"
    EFFECT_ATTEMPT = "effect_attempt"
    EGRESS = "egress"
    TELEMETRY_GAP = "telemetry_gap"
    DETECTOR_FAILURE = "detector_failure"


class HuntState(str, Enum):
    NO_HYPOTHESIS = "no_hypothesis"
    HYPOTHESIS = "hypothesis"
    UNKNOWN = "unknown"


class Severity(IntEnum):
    INFO = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class Disposition(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class HuntEvent:
    event_id: str
    case_id: str
    tenant_id: str
    subject_id: str
    run_id: str
    event_time_ms: int
    kind: EventKind
    evidence_ids: tuple[str, ...]
    attributes: Mapping[str, str | int | bool] = field(default_factory=dict)


@dataclass(frozen=True)
class HuntCase:
    case_id: str
    population: Population
    tenant_id: str
    family: str
    attack_expected: bool
    description: str


@dataclass(frozen=True)
class TenantProfile:
    tenant_id: str
    known_destinations: frozenset[str]
    max_sensitive_resources: int
    max_unique_peers: int
    max_approval_denials: int
    hunt_window_ms: int = 900_000


@dataclass(frozen=True)
class SequenceFeatures:
    tenant_id: str
    subject_id: str
    event_ids: tuple[str, ...]
    sensitive_resources: tuple[str, ...]
    unique_peers: tuple[str, ...]
    approval_denials: int
    effect_after_denials: bool
    unknown_destinations: tuple[str, ...]
    complete: bool
    first_event_ms: int
    last_event_ms: int


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    rule_id: str
    family: str
    severity: Severity
    tenant_id: str
    summary: str
    evidence_ids: tuple[str, ...]
    first_suspicious_ms: int
    detected_at_ms: int
    disposition: Disposition = Disposition.OPEN
    analyst_id: str | None = None
    disposition_evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    population: Population
    state: HuntState
    hypotheses: tuple[Hypothesis, ...]
    features: SequenceFeatures | None
    detection_latency_ms: int | None
    evidence_coverage: float
    evidence_events: int
    window_events: int

    @property
    def alerted(self) -> bool:
        return self.state is HuntState.HYPOTHESIS


@dataclass(frozen=True)
class SuiteReport:
    results: tuple[CaseResult, ...]
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    alerts_per_100_cases: float
    tenant_false_positive_rates: Mapping[str, float]
    macro_tenant_false_positive_rate: float
    mean_detection_latency_ms: float | None
    unknown_rate: float
    evidence_coverage: float


DEFAULT_PROFILES = {
    "tenant-a": TenantProfile(
        "tenant-a", frozenset({"support.example", "api.vendor.example"}),
        max_sensitive_resources=3, max_unique_peers=3, max_approval_denials=2,
    ),
    "tenant-b": TenantProfile(
        "tenant-b", frozenset({"casework.example", "batch.vendor.example"}),
        max_sensitive_resources=4, max_unique_peers=5, max_approval_denials=3,
    ),
}


def canonical_host(value: str) -> str:
    """Canonicalize a URL host without accepting user-info or an absent host."""
    parsed = urlsplit(value)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError("destination must be an absolute URL without user-info")
    return parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()


def course_cases() -> tuple[HuntCase, ...]:
    return (
        HuntCase("valid-support", Population.VALID, "tenant-a", "normal", False, "ordinary support lookup and known egress"),
        HuntCase("valid-batch", Population.VALID, "tenant-b", "normal", False, "authorized high-fan-out batch below tenant-B baseline"),
        HuntCase("valid-approval", Population.VALID, "tenant-a", "normal", False, "two denied approvals with no effect attempt"),
        HuntCase("attack-scope", Population.ATTACK, "tenant-a", "scope-probing", True, "four sensitive resources in one run"),
        HuntCase("attack-slow-scope", Population.ATTACK, "tenant-a", "scope-probing", True, "four sensitive resources spread across runs"),
        HuntCase("attack-fanout", Population.ATTACK, "tenant-a", "fan-out", True, "delegation exceeds tenant-A peer baseline"),
        HuntCase("attack-approval", Population.ATTACK, "tenant-b", "approval-pressure", True, "repeated denial followed by effect attempt"),
        HuntCase("attack-egress", Population.ATTACK, "tenant-a", "destination-drift", True, "direct unknown egress destination"),
        HuntCase("attack-encoded-egress", Population.ATTACK, "tenant-a", "destination-drift", True, "Unicode-lookalike egress destination"),
        HuntCase("boundary-threshold", Population.BOUNDARY, "tenant-a", "threshold", False, "exact sensitive-resource threshold"),
        HuntCase("failure-gap", Population.FAILURE, "tenant-a", "visibility", False, "required telemetry gap"),
        HuntCase("failure-detector", Population.FAILURE, "tenant-b", "dependency", False, "detector dependency unavailable"),
    )


def _event(case: HuntCase, sequence: int, kind: EventKind, *, run: int = 1,
           attributes: Mapping[str, str | int | bool] | None = None,
           event_time_ms: int | None = None) -> HuntEvent:
    return HuntEvent(
        event_id=f"{case.case_id}-e{sequence}", case_id=case.case_id,
        tenant_id=case.tenant_id, subject_id="support-user-17",
        run_id=f"{case.case_id}-run-{run}",
        event_time_ms=event_time_ms if event_time_ms is not None else 1_000 + sequence * 10_000,
        kind=kind, evidence_ids=(f"evidence-{case.case_id}-{sequence}",),
        attributes=attributes or {},
    )


def events_for(case: HuntCase) -> tuple[HuntEvent, ...]:
    """Return deterministic labeled fixtures; these are not production prevalence data."""
    if case.case_id == "valid-support":
        return (
            _event(case, 1, EventKind.RETRIEVAL, attributes={"resource_id": "case-7", "sensitivity": "internal"}),
            _event(case, 2, EventKind.EGRESS, attributes={"destination": "https://support.example/api"}),
        )
    if case.case_id == "valid-batch":
        return tuple(_event(case, index, EventKind.DELEGATION, attributes={"peer_id": f"batch-peer-{index}"}) for index in range(1, 6))
    if case.case_id == "valid-approval":
        return tuple(_event(case, index, EventKind.APPROVAL, attributes={"outcome": "deny"}) for index in range(1, 3))
    if case.case_id in {"attack-scope", "attack-slow-scope", "boundary-threshold"}:
        count = 3 if case.case_id == "boundary-threshold" else 4
        return tuple(
            _event(case, index, EventKind.RETRIEVAL, run=index if case.case_id == "attack-slow-scope" else 1,
                   attributes={"resource_id": f"sensitive-{index}", "sensitivity": "restricted"},
                   event_time_ms=1_000 + index * (180_000 if case.case_id == "attack-slow-scope" else 10_000))
            for index in range(1, count + 1)
        )
    if case.case_id == "attack-fanout":
        return tuple(_event(case, index, EventKind.DELEGATION, attributes={"peer_id": f"peer-{index}"}) for index in range(1, 5))
    if case.case_id == "attack-approval":
        denied = tuple(_event(case, index, EventKind.APPROVAL, attributes={"outcome": "deny"}) for index in range(1, 5))
        return (*denied, _event(case, 5, EventKind.EFFECT_ATTEMPT, attributes={"action": "refund"}))
    if case.case_id == "attack-egress":
        return (_event(case, 1, EventKind.EGRESS, attributes={"destination": "https://exfil.example/upload"}),)
    if case.case_id == "attack-encoded-egress":
        return (_event(case, 1, EventKind.EGRESS, attributes={"destination": "https://exfіl.example/upload"}),)  # Cyrillic і
    if case.case_id == "failure-gap":
        return (
            _event(case, 1, EventKind.RETRIEVAL, attributes={"resource_id": "case-8", "sensitivity": "internal"}),
            _event(case, 2, EventKind.TELEMETRY_GAP, attributes={"reason": "collector-timeout"}),
        )
    if case.case_id == "failure-detector":
        return (_event(case, 1, EventKind.DETECTOR_FAILURE, attributes={"reason": "state-store-unavailable"}),)
    raise KeyError(case.case_id)


def _validate_event(event: HuntEvent) -> None:
    identifiers = (event.event_id, event.case_id, event.tenant_id, event.subject_id, event.run_id)
    if any(not isinstance(item, str) or not item.strip() for item in identifiers):
        raise ValueError("event identifiers and bindings must be non-empty strings")
    if isinstance(event.event_time_ms, bool) or not isinstance(event.event_time_ms, int) or event.event_time_ms < 0:
        raise ValueError("event time must be a non-negative integer")

    required: dict[EventKind, tuple[str, ...]] = {
        EventKind.RETRIEVAL: ("resource_id", "sensitivity"),
        EventKind.DELEGATION: ("peer_id",),
        EventKind.APPROVAL: ("outcome",),
        EventKind.EFFECT_ATTEMPT: ("action",),
        EventKind.EGRESS: ("destination",),
        EventKind.TELEMETRY_GAP: ("reason",),
        EventKind.DETECTOR_FAILURE: ("reason",),
    }
    for attribute in required[event.kind]:
        value = event.attributes.get(attribute)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{event.kind.value} requires string attribute {attribute}")
    if event.kind is EventKind.APPROVAL and event.attributes["outcome"] not in {"allow", "deny"}:
        raise ValueError("approval outcome must be allow or deny")


def extract_features(events: Sequence[HuntEvent], profile: TenantProfile) -> SequenceFeatures:
    if not events:
        raise ValueError("a hunt case requires events")
    tenants = {event.tenant_id for event in events}
    if tenants != {profile.tenant_id}:
        raise ValueError("events must be evaluated against exactly one tenant profile")
    if len({event.event_id for event in events}) != len(events):
        raise ValueError("event identifiers must be unique")
    if profile.hunt_window_ms <= 0:
        raise ValueError("hunt window must be positive")
    for event in events:
        _validate_event(event)
    all_ordered = sorted(events, key=lambda item: (item.event_time_ms, item.event_id))
    window_start = all_ordered[-1].event_time_ms - profile.hunt_window_ms
    ordered = [event for event in all_ordered if event.event_time_ms >= window_start]
    subjects = {event.subject_id for event in ordered}
    if len(subjects) != 1:
        raise ValueError("a hunt sequence must contain exactly one subject")
    sensitive_resources = {
        str(event.attributes.get("resource_id")) for event in ordered
        if event.kind is EventKind.RETRIEVAL and event.attributes.get("sensitivity") == "restricted"
    }
    peers = {
        str(event.attributes.get("peer_id")) for event in ordered
        if event.kind is EventKind.DELEGATION and event.attributes.get("peer_id")
    }
    denied_events = [
        event for event in ordered
        if event.kind is EventKind.APPROVAL and event.attributes.get("outcome") == "deny"
    ]
    denials = len(denied_events)
    last_denial_key = (
        (denied_events[-1].event_time_ms, denied_events[-1].event_id)
        if denied_events else None
    )
    effect_after_denials = last_denial_key is not None and any(
        event.kind is EventKind.EFFECT_ATTEMPT
        and (event.event_time_ms, event.event_id) > last_denial_key
        for event in ordered
    )
    unknown_destinations: set[str] = set()
    for event in ordered:
        if event.kind is EventKind.EGRESS:
            destination = event.attributes.get("destination")
            if not isinstance(destination, str):
                raise ValueError("egress destination must be a string URL")
            host = canonical_host(destination)
            if host not in profile.known_destinations:
                unknown_destinations.add(host)
    complete = not any(event.kind in {EventKind.TELEMETRY_GAP, EventKind.DETECTOR_FAILURE} for event in ordered)
    return SequenceFeatures(
        profile.tenant_id, next(iter(subjects)), tuple(event.event_id for event in ordered),
        tuple(sorted(sensitive_resources)), tuple(sorted(peers)), denials,
        effect_after_denials, tuple(sorted(unknown_destinations)), complete,
        ordered[0].event_time_ms, ordered[-1].event_time_ms,
    )


def _hypothesis(case: HuntCase, rule_id: str, family: str, severity: Severity,
                summary: str, evidence: Sequence[HuntEvent], detected_at_ms: int) -> Hypothesis:
    ids = tuple(evidence_id for event in evidence for evidence_id in event.evidence_ids)
    first = min(event.event_time_ms for event in evidence)
    return Hypothesis(
        hypothesis_id=f"hypothesis-{case.case_id}-{rule_id}", rule_id=rule_id,
        family=family, severity=severity, tenant_id=case.tenant_id,
        summary=summary, evidence_ids=ids, first_suspicious_ms=first,
        detected_at_ms=detected_at_ms,
    )


def _unique_crossing(
    events: Sequence[HuntEvent], attribute: str, maximum: int,
) -> tuple[tuple[HuntEvent, ...], HuntEvent] | None:
    """Return evidence through the event that first exceeds a unique-value limit."""
    seen: set[str] = set()
    evidence: list[HuntEvent] = []
    for event in events:
        value = event.attributes.get(attribute)
        if value is None:
            continue
        evidence.append(event)
        seen.add(str(value))
        if len(seen) > maximum:
            return tuple(evidence), event
    return None


def hunt_case(case: HuntCase, events: Sequence[HuntEvent], profiles: Mapping[str, TenantProfile] = DEFAULT_PROFILES,
              *, naive: bool = False) -> CaseResult:
    supplied_evidence = sum(
        bool(event.evidence_ids)
        and all(isinstance(item, str) and bool(item.strip()) for item in event.evidence_ids)
        for event in events
    )
    profile = profiles.get(case.tenant_id)
    if profile is None:
        return CaseResult(
            case.case_id, case.population, HuntState.UNKNOWN, (), None, None,
            supplied_evidence / len(events) if events else 0.0, supplied_evidence, len(events),
        )
    if not events or any(event.case_id != case.case_id for event in events):
        return CaseResult(
            case.case_id, case.population, HuntState.UNKNOWN, (), None, None,
            supplied_evidence / len(events) if events else 0.0, supplied_evidence, len(events),
        )
    try:
        features = extract_features(events, profile)
    except (KeyError, TypeError, ValueError):
        return CaseResult(
            case.case_id, case.population, HuntState.UNKNOWN, (), None, None,
            supplied_evidence / len(events), supplied_evidence, len(events),
        )
    window_ids = set(features.event_ids)
    ordered = sorted(
        (event for event in events if event.event_id in window_ids),
        key=lambda item: (item.event_time_ms, item.event_id),
    )
    evidence_events = sum(
        bool(event.evidence_ids)
        and all(isinstance(item, str) and bool(item.strip()) for item in event.evidence_ids)
        for event in ordered
    )
    evidence_coverage = evidence_events / len(ordered)
    if not features.complete or evidence_coverage < 1:
        return CaseResult(
            case.case_id, case.population, HuntState.UNKNOWN, (), features, None,
            evidence_coverage, evidence_events, len(ordered),
        )

    hypotheses: list[Hypothesis] = []
    if naive:
        direct = [event for event in ordered if event.kind is EventKind.EGRESS and event.attributes.get("destination") == "https://exfil.example/upload"]
        if direct:
            hypotheses.append(_hypothesis(case, "NAIVE-EXACT-EGRESS", "destination-drift", Severity.HIGH,
                                          "exact blocked destination observed", direct, direct[-1].event_time_ms))
    else:
        restricted = [event for event in ordered if event.kind is EventKind.RETRIEVAL and event.attributes.get("sensitivity") == "restricted"]
        scope_crossing = _unique_crossing(restricted, "resource_id", profile.max_sensitive_resources)
        if scope_crossing:
            evidence, crossing = scope_crossing
            hypotheses.append(_hypothesis(case, "AGENT-SCOPE-PROBE", "scope-probing", Severity.HIGH,
                                          "tenant-normalized sensitive-resource breadth exceeded", evidence, crossing.event_time_ms))
        delegations = [event for event in ordered if event.kind is EventKind.DELEGATION]
        fanout_crossing = _unique_crossing(delegations, "peer_id", profile.max_unique_peers)
        if fanout_crossing:
            evidence, crossing = fanout_crossing
            hypotheses.append(_hypothesis(case, "AGENT-FANOUT-DRIFT", "fan-out", Severity.HIGH,
                                          "unique peer fan-out exceeded the tenant profile", evidence, crossing.event_time_ms))
        denied = [event for event in ordered if event.kind is EventKind.APPROVAL and event.attributes.get("outcome") == "deny"]
        last_denial_key = (
            (denied[-1].event_time_ms, denied[-1].event_id) if denied else None
        )
        effects = [
            event for event in ordered
            if event.kind is EventKind.EFFECT_ATTEMPT
            and last_denial_key is not None
            and (event.event_time_ms, event.event_id) > last_denial_key
        ]
        if features.approval_denials > profile.max_approval_denials and features.effect_after_denials:
            evidence = (*denied, effects[0])
            hypotheses.append(_hypothesis(case, "AGENT-APPROVAL-PRESSURE", "approval-pressure", Severity.CRITICAL,
                                          "repeated approval denials were followed by an effect attempt", evidence, effects[0].event_time_ms))
        unknown = [event for event in ordered if event.kind is EventKind.EGRESS and canonical_host(str(event.attributes["destination"])) in features.unknown_destinations]
        if unknown:
            hypotheses.append(_hypothesis(case, "AGENT-EGRESS-DRIFT", "destination-drift", Severity.CRITICAL,
                                          "egress destination is outside the tenant baseline", unknown, unknown[-1].event_time_ms))

    first_hypothesis = min(hypotheses, key=lambda item: item.detected_at_ms, default=None)
    latency = (
        first_hypothesis.detected_at_ms - first_hypothesis.first_suspicious_ms
        if first_hypothesis else None
    )
    state = HuntState.HYPOTHESIS if hypotheses else HuntState.NO_HYPOTHESIS
    return CaseResult(
        case.case_id, case.population, state, tuple(hypotheses), features, latency,
        evidence_coverage, evidence_events, len(ordered),
    )


def evaluate_suite(cases: Sequence[HuntCase] | None = None, *, naive: bool = False) -> SuiteReport:
    cases = tuple(cases or course_cases())
    if {case.population for case in cases} != set(Population):
        raise ValueError("evaluation requires valid, attack, boundary, and failure populations")
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError("case identifiers must be unique")
    results = tuple(hunt_case(case, events_for(case), naive=naive) for case in cases)
    labels = {case.case_id: case.attack_expected for case in cases}
    tp = sum(labels[result.case_id] and result.alerted for result in results)
    fp = sum(not labels[result.case_id] and result.alerted for result in results)
    # UNKNOWN attack cases remain misses for conservative recall; unknown_rate
    # separately reports how often the detector lacked decision-grade evidence.
    fn = sum(labels[result.case_id] and not result.alerted for result in results)
    tenant_rates: dict[str, float] = {}
    for tenant in sorted({case.tenant_id for case in cases}):
        valid_ids = {case.case_id for case in cases if case.tenant_id == tenant and case.population in {Population.VALID, Population.BOUNDARY}}
        valid_results = [result for result in results if result.case_id in valid_ids]
        tenant_rates[tenant] = sum(result.alerted for result in valid_results) / len(valid_results) if valid_results else 0.0
    latencies = [result.detection_latency_ms for result in results if result.detection_latency_ms is not None]
    return SuiteReport(
        results, tp, fp, fn,
        tp / (tp + fp) if tp + fp else 0.0,
        tp / (tp + fn) if tp + fn else 0.0,
        sum(result.alerted for result in results) / len(results) * 100,
        tenant_rates, sum(tenant_rates.values()) / len(tenant_rates),
        sum(latencies) / len(latencies) if latencies else None,
        sum(result.state is HuntState.UNKNOWN for result in results) / len(results),
        sum(result.evidence_events for result in results) /
        sum(result.window_events for result in results),
    )


def disposition(hypothesis: Hypothesis, decision: Disposition, analyst_id: str,
                supporting_evidence_ids: Sequence[str]) -> Hypothesis:
    if decision is Disposition.OPEN:
        raise ValueError("a completed analyst disposition cannot remain open")
    evidence = tuple(dict.fromkeys(item.strip() for item in supporting_evidence_ids if item.strip()))
    if not analyst_id.strip() or not evidence:
        raise ValueError("disposition requires an accountable analyst and supporting evidence")
    # A disposition records an analyst conclusion; it does not authorize or
    # execute containment. Response remains a separate trusted-application act.
    return replace(
        hypothesis,
        disposition=decision,
        analyst_id=analyst_id.strip(),
        disposition_evidence_ids=evidence,
    )


def validate_rate(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not isfinite(value) or not 0 <= value <= 1:
        raise ValueError("rate must be a finite number in [0, 1]")
    return float(value)


def report_summary(report: SuiteReport) -> dict[str, object]:
    return {
        "precision": report.precision,
        "recall": report.recall,
        "alerts_per_100_cases": report.alerts_per_100_cases,
        "tenant_false_positive_rates": dict(report.tenant_false_positive_rates),
        "macro_tenant_false_positive_rate": report.macro_tenant_false_positive_rate,
        "mean_detection_latency_ms": report.mean_detection_latency_ms,
        "unknown_rate": report.unknown_rate,
        "evidence_coverage": report.evidence_coverage,
        "states": {result.case_id: result.state.value for result in report.results},
    }


def main() -> None:
    print(json.dumps(report_summary(evaluate_suite()), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
