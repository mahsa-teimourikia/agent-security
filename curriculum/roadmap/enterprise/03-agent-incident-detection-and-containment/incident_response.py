"""Deterministic incident detection and containment control plane.

Models may summarize admitted evidence and recommend a response. They cannot
authenticate telemetry, create incidents, define tenant scope, approve actions,
execute containment, verify postconditions, or resolve an incident.

HMAC, integer time, memory stores, and synthetic connectors are credential-free
teaching analogues. Production replacements are described in the course.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from hashlib import sha256
import hmac
import json
from typing import Any


class SignalKind(str, Enum):
    EFFECT_ATTEMPT = "effect-attempt"
    EFFECT_RESULT = "effect-result"
    POLICY_DECISION = "policy-decision"
    IDENTITY_ANOMALY = "identity-anomaly"


class Admission(str, Enum):
    ADMITTED = "admitted"
    IDEMPOTENT = "idempotent"
    DENIED = "denied"


class IncidentState(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINING = "containing"
    CONTAINED = "contained"
    CONTAINMENT_INCOMPLETE = "containment-incomplete"
    RECOVERY_READY = "recovery-ready"
    RESOLVED = "resolved"


class Action(str, Enum):
    DISABLE_AGENT = "disable-agent"
    REVOKE_WRITES = "revoke-writes"
    REVOKE_CREDENTIAL = "revoke-credential"
    BLOCK_DESTINATION = "block-destination"
    PAUSE_QUEUE = "pause-queue"


class ActionOutcome(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    UNKNOWN = "unknown"


def digest(value: Any) -> str:
    def normalize(item: Any) -> Any:
        if isinstance(item, Enum):
            return item.value
        if hasattr(item, "__dataclass_fields__"):
            return normalize(asdict(item))
        if isinstance(item, dict):
            return {str(key): normalize(val) for key, val in sorted(item.items())}
        if isinstance(item, (set, frozenset, tuple, list)):
            values = [normalize(val) for val in item]
            return sorted(values, key=lambda val: json.dumps(val, sort_keys=True))
        return item

    encoded = json.dumps(normalize(value), sort_keys=True, separators=(",", ":"))
    return sha256(encoded.encode()).hexdigest()


@dataclass(frozen=True)
class Producer:
    producer_id: str
    tenant: str
    key_id: str
    secret: bytes
    enabled: bool = True


@dataclass(frozen=True)
class RawSignal:
    event_id: str
    producer_id: str
    tenant: str
    trace_id: str
    run_id: str
    agent_id: str
    kind: SignalKind
    occurred_at: int
    principal_digest: str
    tool: str
    destination: str
    policy_decision: str
    action_id: str
    outcome: str
    checkpoint_id: str
    key_id: str = ""
    signature: str = ""


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    event_id: str
    tenant: str
    producer_id: str
    trace_id: str
    run_id: str
    agent_id: str
    kind: SignalKind
    occurred_at: int
    received_at: int
    principal_digest: str
    tool: str
    destination: str
    policy_decision: str
    action_id: str
    outcome: str
    checkpoint_id: str
    source_digest: str


@dataclass(frozen=True)
class AdmissionReceipt:
    status: Admission
    reason: str
    event_id: str
    evidence_id: str = ""


class SignalSigner:
    @staticmethod
    def payload(signal: RawSignal) -> dict[str, Any]:
        return {key: value for key, value in signal.__dict__.items() if key != "signature"}

    @staticmethod
    def sign(signal: RawSignal, producer: Producer) -> RawSignal:
        unsigned = replace(signal, key_id=producer.key_id, signature="")
        signature = hmac.new(producer.secret, digest(SignalSigner.payload(unsigned)).encode(), sha256).hexdigest()
        return replace(unsigned, signature=signature)

    @staticmethod
    def verify(signal: RawSignal, producer: Producer) -> bool:
        if signal.key_id != producer.key_id:
            return False
        expected = hmac.new(
            producer.secret,
            digest(SignalSigner.payload(replace(signal, signature=""))).encode(),
            sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signal.signature)


@dataclass
class EvidenceStore:
    producers: dict[str, Producer]
    max_age: int = 300
    max_future_skew: int = 5
    evidence: dict[str, Evidence] = field(default_factory=dict)
    event_digests: dict[str, str] = field(default_factory=dict)

    def admit(self, signal: RawSignal, *, received_at: int) -> AdmissionReceipt:
        signal_digest = digest(SignalSigner.payload(signal))
        previous = self.event_digests.get(signal.event_id)
        if previous:
            if previous == signal_digest:
                existing = next(item for item in self.evidence.values() if item.event_id == signal.event_id)
                return AdmissionReceipt(Admission.IDEMPOTENT, "duplicate-delivery", signal.event_id, existing.evidence_id)
            return AdmissionReceipt(Admission.DENIED, "event-id-conflict", signal.event_id)

        producer = self.producers.get(signal.producer_id)
        if not producer or not producer.enabled:
            return AdmissionReceipt(Admission.DENIED, "producer-not-trusted", signal.event_id)
        if producer.tenant != signal.tenant:
            return AdmissionReceipt(Admission.DENIED, "producer-tenant-mismatch", signal.event_id)
        if not SignalSigner.verify(signal, producer):
            return AdmissionReceipt(Admission.DENIED, "invalid-signal-signature", signal.event_id)
        required = (
            signal.event_id, signal.trace_id, signal.run_id, signal.agent_id,
            signal.principal_digest, signal.action_id, signal.checkpoint_id,
        )
        if not all(required):
            return AdmissionReceipt(Admission.DENIED, "required-evidence-missing", signal.event_id)
        if signal.occurred_at > received_at + self.max_future_skew:
            return AdmissionReceipt(Admission.DENIED, "signal-from-future", signal.event_id)
        if received_at - signal.occurred_at > self.max_age:
            return AdmissionReceipt(Admission.DENIED, "signal-too-old", signal.event_id)

        evidence_id = f"evidence:{signal.event_id}"
        admitted = Evidence(
            evidence_id, signal.event_id, signal.tenant, signal.producer_id,
            signal.trace_id, signal.run_id, signal.agent_id, signal.kind,
            signal.occurred_at, received_at, signal.principal_digest, signal.tool,
            signal.destination, signal.policy_decision, signal.action_id,
            signal.outcome, signal.checkpoint_id, signal_digest,
        )
        self.evidence[evidence_id] = admitted
        self.event_digests[signal.event_id] = signal_digest
        return AdmissionReceipt(Admission.ADMITTED, "verified-evidence", signal.event_id, evidence_id)


@dataclass(frozen=True)
class CandidateAlert:
    alert_id: str
    fingerprint: str
    tenant: str
    rule_id: str
    rule_version: str
    severity: str
    evidence_ids: tuple[str, ...]
    run_id: str
    agent_id: str
    destination: str


@dataclass
class DetectionEngine:
    allowed_destinations: frozenset[str]
    rule_id: str = "agent-unapproved-committed-egress"
    rule_version: str = "2026-11-01"

    def detect(self, evidence: Evidence) -> CandidateAlert | None:
        if (
            evidence.kind is not SignalKind.EFFECT_RESULT
            or evidence.destination in self.allowed_destinations
            or evidence.outcome != "committed"
        ):
            return None
        fingerprint = digest({
            "tenant": evidence.tenant,
            "run": evidence.run_id,
            "agent": evidence.agent_id,
            "destination": evidence.destination,
            "rule": self.rule_id,
            "version": self.rule_version,
        })
        return CandidateAlert(
            f"alert:{fingerprint[:16]}", fingerprint, evidence.tenant,
            self.rule_id, self.rule_version, "critical", (evidence.evidence_id,),
            evidence.run_id, evidence.agent_id, evidence.destination,
        )


@dataclass(frozen=True)
class RunAssets:
    tenant: str
    run_id: str
    agent_id: str
    credential_id: str
    queue_id: str


@dataclass(frozen=True)
class IncidentScope:
    tenant: str
    run_ids: frozenset[str]
    agent_ids: frozenset[str]
    credential_ids: frozenset[str]
    queue_ids: frozenset[str]
    destinations: frozenset[str]
    complete: bool

    @property
    def scope_digest(self) -> str:
        return digest(self)


@dataclass
class AssetGraph:
    runs: dict[str, RunAssets]

    def scope(self, alert: CandidateAlert) -> IncidentScope:
        asset = self.runs.get(alert.run_id)
        if not asset or asset.tenant != alert.tenant or asset.agent_id != alert.agent_id:
            return IncidentScope(alert.tenant, frozenset({alert.run_id}), frozenset({alert.agent_id}),
                                 frozenset(), frozenset(), frozenset({alert.destination}), False)
        return IncidentScope(
            alert.tenant, frozenset({asset.run_id}), frozenset({asset.agent_id}),
            frozenset({asset.credential_id}), frozenset({asset.queue_id}),
            frozenset({alert.destination}), True,
        )


@dataclass
class Incident:
    incident_id: str
    tenant: str
    fingerprint: str
    state: IncidentState
    version: int
    severity: str
    evidence_ids: tuple[str, ...]
    scope: IncidentScope
    model_summary: str = ""
    action_receipts: tuple["ActionReceipt", ...] = ()
    containment_approved_by: str = ""


@dataclass
class IncidentManager:
    evidence_store: EvidenceStore
    detectors: dict[tuple[str, str], DetectionEngine]
    incidents: dict[str, Incident] = field(default_factory=dict)
    by_fingerprint: dict[str, str] = field(default_factory=dict)

    def promote(self, alert: CandidateAlert, scope: IncidentScope, *, model_summary: str = "") -> Incident:
        detector = self.detectors.get((alert.rule_id, alert.rule_version))
        if detector is None:
            raise PermissionError("detection-rule-not-accepted")
        admitted = [self.evidence_store.evidence.get(evidence_id) for evidence_id in alert.evidence_ids]
        if not admitted or any(item is None for item in admitted):
            raise PermissionError("admitted-evidence-required")
        if any(
            (item.tenant, item.run_id, item.agent_id) != (alert.tenant, alert.run_id, alert.agent_id)
            for item in admitted if item is not None
        ):
            raise PermissionError("alert-evidence-binding-mismatch")
        reproduced = [detector.detect(item) for item in admitted if item is not None]
        if alert not in reproduced:
            raise PermissionError("alert-not-reproducible")
        if scope.tenant != alert.tenant:
            raise PermissionError("alert-scope-tenant-mismatch")
        existing_id = self.by_fingerprint.get(alert.fingerprint)
        if existing_id:
            return self.incidents[existing_id]
        incident_id = f"incident:{alert.fingerprint[:16]}"
        incident = Incident(
            incident_id, alert.tenant, alert.fingerprint, IncidentState.TRIAGED,
            1, alert.severity, alert.evidence_ids, scope, model_summary,
        )
        self.incidents[incident_id] = incident
        self.by_fingerprint[alert.fingerprint] = incident_id
        return incident


@dataclass(frozen=True)
class Responder:
    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class ContainmentPlan:
    plan_id: str
    incident_id: str
    tenant: str
    expected_incident_version: int
    scope_digest: str
    actions: tuple[Action, ...]
    policy_version: str
    approved_by: str
    issued_at: int
    expires_at: int
    key_id: str = ""
    signature: str = ""


class PlanSigner:
    def __init__(self, key_id: str = "response-key-2026-11", secret: bytes = b"course-only-response-key"):
        self.key_id = key_id
        self._secret = secret

    @staticmethod
    def payload(plan: ContainmentPlan) -> dict[str, Any]:
        return {key: value for key, value in plan.__dict__.items() if key != "signature"}

    def sign(self, plan: ContainmentPlan) -> ContainmentPlan:
        unsigned = replace(plan, key_id=self.key_id, signature="")
        signature = hmac.new(self._secret, digest(self.payload(unsigned)).encode(), sha256).hexdigest()
        return replace(unsigned, signature=signature)

    def verify(self, plan: ContainmentPlan) -> bool:
        if plan.key_id != self.key_id:
            return False
        expected = hmac.new(
            self._secret,
            digest(self.payload(replace(plan, signature=""))).encode(),
            sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, plan.signature)


@dataclass(frozen=True)
class ActionReceipt:
    operation_id: str
    action: Action
    outcome: ActionOutcome
    verified: bool
    reason: str
    target_digest: str
    observed_at: int


@dataclass(frozen=True)
class ConnectorResult:
    operation_id: str
    action: Action
    outcome: ActionOutcome
    reason: str


@dataclass
class SyntheticConnector:
    outcomes: dict[Action, tuple[ActionOutcome, bool]] = field(default_factory=dict)
    calls: dict[str, ConnectorResult] = field(default_factory=dict)
    raise_actions: frozenset[Action] = frozenset()

    def execute(self, operation_id: str, action: Action, target: str, *, now: int) -> ConnectorResult:
        if operation_id in self.calls:
            return self.calls[operation_id]
        if action in self.raise_actions:
            raise ConnectionError(f"connector-unavailable:{action.value}")
        outcome, _ = self.outcomes.get(action, (ActionOutcome.SUCCESS, True))
        result = ConnectorResult(operation_id, action, outcome, f"connector-{outcome.value}")
        self.calls[operation_id] = result
        return result

    def verify_postcondition(self, action: Action, target: str) -> bool | None:
        """Independent authoritative-state query analogue."""
        del target
        _, verified = self.outcomes.get(action, (ActionOutcome.SUCCESS, True))
        return verified


@dataclass(frozen=True)
class PlanResult:
    accepted: bool
    reason: str
    incident_state: IncidentState
    receipts: tuple[ActionReceipt, ...] = ()


@dataclass
class ContainmentService:
    signer: PlanSigner = field(default_factory=PlanSigner)
    used_plans: set[str] = field(default_factory=set)
    current_policy_version: str = "response-policy-2026-11"

    def execute(self, incident: Incident, plan: ContainmentPlan, responder: Responder,
                connector: SyntheticConnector, *, now: int) -> PlanResult:
        reason = self._validate(incident, plan, responder, now)
        if reason:
            return PlanResult(False, reason, incident.state)
        # Teaching analogue for an atomic plan-consumption transaction.
        self.used_plans.add(plan.plan_id)
        incident.state = IncidentState.CONTAINING
        incident.version += 1
        receipts_list: list[ActionReceipt] = []
        for action in plan.actions:
            operation_id = f"{plan.plan_id}:{action.value}"
            target = self._target(incident.scope, action)
            try:
                connector_result = connector.execute(operation_id, action, target, now=now)
                postcondition = connector.verify_postcondition(action, target)
                verified = connector_result.outcome is ActionOutcome.SUCCESS and postcondition is True
                reason = "postcondition-verified" if verified else (
                    "postcondition-unverified" if connector_result.outcome is ActionOutcome.SUCCESS
                    else connector_result.reason
                )
                receipt = ActionReceipt(
                    operation_id, action, connector_result.outcome, verified, reason,
                    digest(target)[:16], now,
                )
            except ConnectionError:
                receipt = ActionReceipt(
                    operation_id, action, ActionOutcome.UNKNOWN, False,
                    "connector-exception", digest(target)[:16], now,
                )
            receipts_list.append(receipt)
        receipts = tuple(receipts_list)
        complete = all(
            receipt.outcome is ActionOutcome.SUCCESS and receipt.verified
            for receipt in receipts
        )
        incident.action_receipts = receipts
        incident.containment_approved_by = responder.subject
        incident.state = IncidentState.CONTAINED if complete else IncidentState.CONTAINMENT_INCOMPLETE
        incident.version += 1
        return PlanResult(True, "containment-verified" if complete else "containment-incomplete",
                          incident.state, receipts)

    def _validate(self, incident: Incident, plan: ContainmentPlan, responder: Responder, now: int) -> str:
        if not responder.authenticated:
            return "responder-not-authenticated"
        if "incident_commander" not in responder.roles:
            return "incident-commander-required"
        if responder.subject != plan.approved_by:
            return "approver-binding-mismatch"
        if responder.tenant != plan.tenant or incident.tenant != plan.tenant:
            return "tenant-mismatch"
        if not self.signer.verify(plan):
            return "invalid-plan-signature"
        if plan.plan_id in self.used_plans:
            return "plan-already-used"
        if plan.incident_id != incident.incident_id:
            return "incident-binding-mismatch"
        if plan.expected_incident_version != incident.version:
            return "incident-version-conflict"
        if plan.scope_digest != incident.scope.scope_digest:
            return "scope-changed"
        if not incident.scope.complete:
            return "scope-incomplete"
        if plan.policy_version != self.current_policy_version:
            return "response-policy-changed"
        if now < plan.issued_at or now >= plan.expires_at:
            return "plan-not-current"
        required = set(Action)
        if set(plan.actions) != required or len(plan.actions) != len(required):
            return "required-action-set-mismatch"
        return ""

    @staticmethod
    def _target(scope: IncidentScope, action: Action) -> str:
        mapping = {
            Action.DISABLE_AGENT: scope.agent_ids,
            Action.REVOKE_WRITES: scope.agent_ids,
            Action.REVOKE_CREDENTIAL: scope.credential_ids,
            Action.BLOCK_DESTINATION: scope.destinations,
            Action.PAUSE_QUEUE: scope.queue_ids,
        }
        return ",".join(sorted(mapping[action]))


@dataclass(frozen=True)
class VaultRecord:
    sequence: int
    incident_id: str
    kind: str
    payload_digest: str
    previous_digest: str
    record_digest: str


@dataclass
class EvidenceVault:
    records: list[VaultRecord] = field(default_factory=list)

    def append(self, incident_id: str, kind: str, payload: Any) -> VaultRecord:
        previous = self.records[-1].record_digest if self.records else "GENESIS"
        sequence = len(self.records) + 1
        payload_digest = digest(payload)
        record_digest = digest({
            "sequence": sequence, "incident_id": incident_id, "kind": kind,
            "payload_digest": payload_digest, "previous_digest": previous,
        })
        record = VaultRecord(sequence, incident_id, kind, payload_digest, previous, record_digest)
        self.records.append(record)
        return record

    def verify(self) -> bool:
        previous = "GENESIS"
        for record in self.records:
            expected = digest({
                "sequence": record.sequence, "incident_id": record.incident_id,
                "kind": record.kind, "payload_digest": record.payload_digest,
                "previous_digest": previous,
            })
            if record.previous_digest != previous or record.record_digest != expected:
                return False
            previous = record.record_digest
        return True


@dataclass(frozen=True)
class RecoveryHandoff:
    incident_id: str
    incident_version: int
    root_cause_evidence_id: str
    remediation_id: str
    regression_suite_id: str
    policy_version: str
    approved_by: str


def prepare_recovery_handoff(incident: Incident, responder: Responder, *,
                             root_cause_evidence_id: str, remediation_id: str,
                             regression_suite_id: str, policy_version: str,
                             current_policy_version: str) -> RecoveryHandoff:
    if not responder.authenticated or "recovery_approver" not in responder.roles:
        raise PermissionError("recovery-approver-required")
    if responder.tenant != incident.tenant:
        raise PermissionError("tenant-mismatch")
    if incident.state is not IncidentState.CONTAINED:
        raise RuntimeError("verified-containment-required")
    if responder.subject == incident.containment_approved_by:
        raise PermissionError("recovery-separation-required")
    if not all((root_cause_evidence_id, remediation_id, regression_suite_id)):
        raise ValueError("recovery-evidence-incomplete")
    if policy_version != current_policy_version:
        raise PermissionError("recovery-policy-stale")
    if not all(r.outcome is ActionOutcome.SUCCESS and r.verified for r in incident.action_receipts):
        raise RuntimeError("containment-postcondition-missing")
    incident.state = IncidentState.RECOVERY_READY
    incident.version += 1
    return RecoveryHandoff(
        incident.incident_id, incident.version, root_cause_evidence_id,
        remediation_id, regression_suite_id, policy_version, responder.subject,
    )


@dataclass(frozen=True)
class EvaluationReport:
    valid_cases: int
    attack_cases: int
    boundary_cases: int
    failure_cases: int
    incident_detection_recall: float
    benign_promotion_rate: float
    unauthorized_signal_admission_rate: float
    duplicate_incident_rate: float
    verified_containment_rate: float
    recovery_without_containment_rate: float


def build_system() -> tuple[Producer, EvidenceStore, DetectionEngine, AssetGraph, IncidentManager]:
    producer = Producer("otel-gateway:north", "north", "telemetry-key-2026-11", b"course-telemetry-key")
    store = EvidenceStore({producer.producer_id: producer})
    detector = DetectionEngine(frozenset({"support.internal", "case-store.internal"}))
    graph = AssetGraph({
        "run:north:42": RunAssets("north", "run:north:42", "support-7", "credential:north:7", "queue:north:support")
    })
    manager = IncidentManager(store, {(detector.rule_id, detector.rule_version): detector})
    return producer, store, detector, graph, manager


def signed_signal(producer: Producer, *, event_id: str = "event:egress:42",
                  destination: str = "collector.evil", outcome: str = "committed",
                  kind: SignalKind = SignalKind.EFFECT_RESULT, tenant: str = "north",
                  occurred_at: int = 100) -> RawSignal:
    signal = RawSignal(
        event_id, producer.producer_id, tenant, "trace:north:42", "run:north:42",
        "support-7", kind, occurred_at, digest("principal:north:alice")[:16],
        "http.post", destination, "allow", "action:42", outcome,
        "checkpoint:north:42",
    )
    return SignalSigner.sign(signal, producer)


def open_incident() -> tuple[Incident, Producer, EvidenceStore, ContainmentService, Responder]:
    producer, store, detector, graph, manager = build_system()
    signal = signed_signal(producer)
    admission = store.admit(signal, received_at=101)
    evidence = store.evidence[admission.evidence_id]
    alert = detector.detect(evidence)
    assert alert
    incident = manager.promote(alert, graph.scope(alert), model_summary="Model recommends resolving immediately")
    service = ContainmentService()
    responder = Responder("commander:north:1", "north", frozenset({"incident_commander"}))
    return incident, producer, store, service, responder


def approved_plan(incident: Incident, service: ContainmentService, responder: Responder,
                  *, plan_id: str = "plan:contain:42", now: int = 110) -> ContainmentPlan:
    plan = ContainmentPlan(
        plan_id, incident.incident_id, incident.tenant, incident.version,
        incident.scope.scope_digest, tuple(Action), service.current_policy_version,
        responder.subject, now, now + 30,
    )
    return service.signer.sign(plan)


def evaluate_controls() -> EvaluationReport:
    producer, store, detector, graph, manager = build_system()
    malicious = signed_signal(producer)
    benign = signed_signal(producer, event_id="event:benign", destination="support.internal")
    forged = replace(signed_signal(producer, event_id="event:forged"), destination="other.evil")

    malicious_receipt = store.admit(malicious, received_at=101)
    benign_receipt = store.admit(benign, received_at=101)
    forged_receipt = store.admit(forged, received_at=101)
    duplicate_receipt = store.admit(malicious, received_at=102)

    alert = detector.detect(store.evidence[malicious_receipt.evidence_id])
    benign_alert = detector.detect(store.evidence[benign_receipt.evidence_id])
    assert alert
    first = manager.promote(alert, graph.scope(alert))
    duplicate = manager.promote(alert, graph.scope(alert))

    service = ContainmentService()
    responder = Responder("commander:north:1", "north", frozenset({"incident_commander"}))
    connector = SyntheticConnector({Action.BLOCK_DESTINATION: (ActionOutcome.UNKNOWN, False)})
    result = service.execute(first, approved_plan(first, service, responder), responder, connector, now=111)
    try:
        prepare_recovery_handoff(
            first, Responder("risk:north:2", "north", frozenset({"recovery_approver"})),
            root_cause_evidence_id="evidence:root", remediation_id="fix:1",
            regression_suite_id="suite:1", policy_version=service.current_policy_version,
            current_policy_version=service.current_policy_version,
        )
        recovery_bypass = 1
    except RuntimeError:
        recovery_bypass = 0

    return EvaluationReport(
        valid_cases=2,
        attack_cases=1,
        boundary_cases=1,
        failure_cases=1,
        incident_detection_recall=1.0 if alert else 0.0,
        benign_promotion_rate=1.0 if benign_alert else 0.0,
        unauthorized_signal_admission_rate=1.0 if forged_receipt.status is not Admission.DENIED else 0.0,
        duplicate_incident_rate=1.0 if first.incident_id != duplicate.incident_id else 0.0,
        verified_containment_rate=1.0 if result.incident_state is IncidentState.CONTAINED else 0.0,
        recovery_without_containment_rate=float(recovery_bypass),
    )
