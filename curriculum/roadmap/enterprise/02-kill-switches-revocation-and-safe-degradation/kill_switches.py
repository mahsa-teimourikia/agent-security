"""Deterministic enterprise kill-switch and safe-degradation teaching lab.

The model proposes work; an independently operated control plane changes
authority; trusted enforcement points authorize scheduling and every external
effect. HMAC, memory stores, and logical time are credential-free teaching
analogues, not production control-plane components.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from hashlib import sha256
import hmac
import json
from typing import Any


class Capability(str, Enum):
    SCHEDULE = "schedule"
    WRITE = "write"
    TOOL = "tool"
    CREDENTIAL = "credential"
    RETRIEVAL = "retrieval"
    MCP = "mcp"
    EGRESS = "egress"
    DIAGNOSTIC_READ = "diagnostic-read"


class Mode(str, Enum):
    ACTIVE = "active"
    READ_ONLY = "read-only"
    QUARANTINED = "quarantined"
    STOPPED = "stopped"


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


class EffectState(str, Enum):
    PREPARED = "prepared"
    IN_FLIGHT = "in-flight"
    CANCELED = "canceled"
    COMMITTED = "committed"
    UNKNOWN = "unknown"


MODE_RANK = {Mode.ACTIVE: 0, Mode.READ_ONLY: 1, Mode.QUARANTINED: 2, Mode.STOPPED: 3}
CONSEQUENTIAL = frozenset(
    {Capability.SCHEDULE, Capability.WRITE, Capability.TOOL, Capability.CREDENTIAL,
     Capability.RETRIEVAL, Capability.MCP, Capability.EGRESS}
)


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
class Principal:
    subject: str
    tenant: str
    scopes: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class Operator:
    subject: str
    tenant: str
    roles: frozenset[str]
    authenticated: bool = True


@dataclass(frozen=True)
class ControlCommand:
    command_id: str
    incident_id: str
    tenant: str
    agent_id: str
    epoch: int
    issued_at: int
    reason_code: str
    mode: Mode | None = None
    revoke: frozenset[Capability] = frozenset()
    block_destinations: frozenset[str] = frozenset()
    restore: frozenset[Capability] = frozenset()
    recovery_plan_id: str = ""
    key_id: str = ""
    signature: str = ""


@dataclass(frozen=True)
class ControlSnapshot:
    tenant: str
    agent_id: str
    epoch: int
    activated_at: int
    mode: Mode
    revoked: frozenset[Capability]
    blocked_destinations: frozenset[str]
    command_ids: tuple[str, ...]

    @property
    def snapshot_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class ControlReceipt:
    command_id: str
    epoch: int
    outcome: Outcome
    reason: str
    operator_subject_digest: str
    snapshot_digest: str


@dataclass(frozen=True)
class RecoveryPlan:
    plan_id: str
    incident_id: str
    tenant: str
    agent_id: str
    from_epoch: int
    to_epoch: int
    approved_by: str
    expires_at: int


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str
    boundary: str
    control_epoch: int
    observed_at: int


@dataclass
class EffectRecord:
    operation_id: str
    capability: Capability
    destination: str
    prepared_at: int
    state: EffectState = EffectState.PREPARED
    provider_reference: str = ""


class CommandSigner:
    """HMAC analogue for authenticated, integrity-protected distribution."""

    def __init__(self, key_id: str = "ops-key-2026-10", secret: bytes = b"course-only-secret"):
        self.key_id = key_id
        self._secret = secret

    @staticmethod
    def payload(command: ControlCommand) -> dict[str, Any]:
        return {key: value for key, value in command.__dict__.items() if key != "signature"}

    def sign(self, command: ControlCommand) -> ControlCommand:
        unsigned = replace(command, key_id=self.key_id, signature="")
        signature = hmac.new(self._secret, digest(self.payload(unsigned)).encode(), sha256).hexdigest()
        return replace(unsigned, signature=signature)

    def verify(self, command: ControlCommand) -> bool:
        if command.key_id != self.key_id:
            return False
        expected = hmac.new(self._secret, digest(self.payload(replace(command, signature=""))).encode(), sha256).hexdigest()
        return hmac.compare_digest(expected, command.signature)


class ControlPlane:
    """Independent authority for deny-first changes and approved recovery."""

    def __init__(self, tenant: str = "north", agent_id: str = "support-7") -> None:
        self.signer = CommandSigner()
        self.snapshot = ControlSnapshot(tenant, agent_id, 0, 0, Mode.ACTIVE, frozenset(), frozenset(), ())
        self.receipts: list[ControlReceipt] = []
        self._command_receipts: dict[str, ControlReceipt] = {}
        self.recovery_plans: dict[str, RecoveryPlan] = {}
        self._used_plans: set[str] = set()

    def approve_recovery(self, plan: RecoveryPlan, approver: Operator) -> None:
        if not approver.authenticated or "recovery_approver" not in approver.roles:
            raise PermissionError("recovery-approver-required")
        if approver.subject != plan.approved_by or approver.tenant != plan.tenant:
            raise PermissionError("recovery-plan-binding-mismatch")
        self.recovery_plans[plan.plan_id] = plan

    def activate(self, operator: Operator, command: ControlCommand, *, activated_at: int) -> ControlReceipt:
        previous = self._command_receipts.get(command.command_id)
        if previous:
            return previous
        reason = self._validate(operator, command, activated_at)
        if reason:
            receipt = self._receipt(command, Outcome.DENY, reason, operator, self.snapshot)
            self.receipts.append(receipt)
            return receipt

        recovery = bool(command.restore or command.mode is Mode.ACTIVE)
        if recovery:
            plan = self.recovery_plans[command.recovery_plan_id]
            revoked = self.snapshot.revoked - command.restore
            mode = command.mode or self.snapshot.mode
            self._used_plans.add(plan.plan_id)
        else:
            revoked = self.snapshot.revoked | command.revoke
            proposed = command.mode or self.snapshot.mode
            mode = proposed if MODE_RANK[proposed] >= MODE_RANK[self.snapshot.mode] else self.snapshot.mode

        snapshot = ControlSnapshot(
            command.tenant, command.agent_id, command.epoch, activated_at, mode,
            frozenset(revoked), self.snapshot.blocked_destinations | command.block_destinations,
            self.snapshot.command_ids + (command.command_id,),
        )
        self.snapshot = snapshot
        receipt = self._receipt(command, Outcome.ALLOW, "activated", operator, snapshot)
        self.receipts.append(receipt)
        self._command_receipts[command.command_id] = receipt
        return receipt

    def _validate(self, operator: Operator, command: ControlCommand, now: int) -> str:
        if not operator.authenticated:
            return "operator-not-authenticated"
        if "incident_commander" not in operator.roles:
            return "incident-commander-required"
        if operator.tenant != command.tenant or command.tenant != self.snapshot.tenant:
            return "tenant-mismatch"
        if command.agent_id != self.snapshot.agent_id:
            return "agent-mismatch"
        if not self.signer.verify(command):
            return "invalid-command-signature"
        if command.epoch != self.snapshot.epoch + 1:
            return "non-monotonic-epoch"
        if not command.incident_id or not command.reason_code:
            return "incident-and-reason-required"
        recovery = bool(command.restore or command.mode is Mode.ACTIVE)
        if recovery:
            plan = self.recovery_plans.get(command.recovery_plan_id)
            if not plan or plan.plan_id in self._used_plans:
                return "fresh-recovery-plan-required"
            if (plan.incident_id, plan.tenant, plan.agent_id) != (command.incident_id, command.tenant, command.agent_id):
                return "recovery-plan-binding-mismatch"
            if (plan.from_epoch, plan.to_epoch) != (self.snapshot.epoch, command.epoch):
                return "recovery-plan-epoch-mismatch"
            if plan.approved_by == operator.subject:
                return "recovery-separation-required"
            if now >= plan.expires_at:
                return "recovery-plan-expired"
        elif command.mode and MODE_RANK[command.mode] < MODE_RANK[self.snapshot.mode]:
            return "recovery-plan-required"
        return ""

    @staticmethod
    def _receipt(command: ControlCommand, outcome: Outcome, reason: str, operator: Operator,
                 snapshot: ControlSnapshot) -> ControlReceipt:
        return ControlReceipt(command.command_id, command.epoch, outcome, reason,
                              digest(operator.subject)[:16], snapshot.snapshot_digest)


@dataclass
class EnforcementPoint:
    name: str
    tenant: str
    agent_id: str
    max_staleness: int = 5
    snapshot: ControlSnapshot | None = None
    observed_at: int = -1

    def observe(self, snapshot: ControlSnapshot, *, observed_at: int) -> bool:
        if (snapshot.tenant, snapshot.agent_id) != (self.tenant, self.agent_id):
            return False
        if self.snapshot and snapshot.epoch < self.snapshot.epoch:
            return False
        if self.snapshot and snapshot.epoch == self.snapshot.epoch:
            if snapshot.snapshot_digest != self.snapshot.snapshot_digest:
                return False
            # Idempotent redelivery is valid, but replay cannot refresh the
            # freshness clock and keep an old epoch authoritative forever.
            return True
        self.snapshot, self.observed_at = snapshot, observed_at
        return True

    def authorize(self, principal: Principal, capability: Capability, *, destination: str,
                  now: int, boundary: str, current_policy: bool = True) -> Decision:
        epoch = self.snapshot.epoch if self.snapshot else -1
        if not principal.authenticated:
            return Decision(Outcome.DENY, "principal-not-authenticated", boundary, epoch, now)
        if principal.tenant != self.tenant:
            return Decision(Outcome.DENY, "tenant-mismatch", boundary, epoch, now)
        if capability.value not in principal.scopes:
            return Decision(Outcome.DENY, "scope-denied", boundary, epoch, now)
        if not current_policy:
            return Decision(Outcome.DENY, "policy-stale", boundary, epoch, now)
        if not self.snapshot:
            return Decision(Outcome.DENY, "control-snapshot-missing", boundary, epoch, now)
        stale = now - self.observed_at > self.max_staleness
        if stale and capability in CONSEQUENTIAL:
            return Decision(Outcome.DENY, "control-snapshot-stale", boundary, epoch, now)
        if capability in self.snapshot.revoked:
            return Decision(Outcome.DENY, "capability-revoked", boundary, epoch, now)
        if destination in self.snapshot.blocked_destinations:
            return Decision(Outcome.DENY, "destination-blocked", boundary, epoch, now)
        if self.snapshot.mode is Mode.STOPPED:
            return Decision(Outcome.DENY, "agent-stopped", boundary, epoch, now)
        if self.snapshot.mode is Mode.QUARANTINED and capability is not Capability.DIAGNOSTIC_READ:
            return Decision(Outcome.DENY, "agent-quarantined", boundary, epoch, now)
        if self.snapshot.mode is Mode.READ_ONLY and capability in CONSEQUENTIAL:
            return Decision(Outcome.DENY, "read-only-mode", boundary, epoch, now)
        reason = "diagnostic-under-stale-control" if stale else "authorized"
        return Decision(Outcome.ALLOW, reason, boundary, epoch, now)


@dataclass
class SyntheticProvider:
    supports_cancel: bool
    committed: dict[str, EffectRecord] = field(default_factory=dict)

    def dispatch(self, record: EffectRecord, *, commit: bool = False) -> EffectRecord:
        record.state = EffectState.COMMITTED if commit else EffectState.IN_FLIGHT
        record.provider_reference = f"provider:{digest(record.operation_id)[:12]}"
        if commit:
            self.committed[record.operation_id] = replace(record)
        return record

    def contain(self, record: EffectRecord) -> EffectRecord:
        if record.state is EffectState.COMMITTED:
            return record
        record.state = EffectState.CANCELED if self.supports_cancel else EffectState.UNKNOWN
        return record

    def reconcile(self, record: EffectRecord) -> EffectRecord:
        committed = self.committed.get(record.operation_id)
        record.state = EffectState.COMMITTED if committed else EffectState.CANCELED
        return record


@dataclass(frozen=True)
class EvaluationReport:
    valid_cases: int
    attack_cases: int
    boundary_cases: int
    failure_cases: int
    valid_diagnostic_retention_rate: float
    unsafe_effect_rate: float
    stale_snapshot_safe_denial_rate: float
    recovery_bypass_rate: float
    propagation_slo_rate: float


def signed_command(plane: ControlPlane, *, command_id: str, epoch: int, mode: Mode | None = None,
                   revoke: frozenset[Capability] = frozenset(),
                   block_destinations: frozenset[str] = frozenset(),
                   restore: frozenset[Capability] = frozenset(),
                   recovery_plan_id: str = "") -> ControlCommand:
    return plane.signer.sign(ControlCommand(
        command_id, "incident-2026-104", plane.snapshot.tenant, plane.snapshot.agent_id,
        epoch, epoch * 10, "confirmed-exfiltration", mode, revoke, block_destinations,
        restore, recovery_plan_id,
    ))


def build_system() -> tuple[ControlPlane, Operator, Principal, EnforcementPoint]:
    plane = ControlPlane()
    operator = Operator("oncall:north:1", "north", frozenset({"incident_commander"}))
    principal = Principal(
        "analyst:north:7", "north",
        frozenset(capability.value for capability in Capability),
    )
    point = EnforcementPoint("effect-gateway", "north", "support-7")
    point.observe(plane.snapshot, observed_at=0)
    return plane, operator, principal, point


def propagation_report(snapshot: ControlSnapshot, observations: dict[str, int], *, deadline: int) -> dict[str, Any]:
    latencies = {name: observed - snapshot.activated_at for name, observed in observations.items()}
    if any(latency < 0 for latency in latencies.values()):
        raise ValueError("observation-before-authoritative-activation")
    within = sum(latency <= deadline for latency in latencies.values())
    return {
        "epoch": snapshot.epoch,
        "latencies": latencies,
        "within_slo": within,
        "expected": len(latencies),
        "slo_rate": within / len(latencies) if latencies else 0.0,
    }


def evaluate_controls() -> EvaluationReport:
    plane, operator, principal, point = build_system()
    containment = signed_command(
        plane, command_id="cmd:contain:1", epoch=1, mode=Mode.READ_ONLY,
        revoke=frozenset({Capability.WRITE, Capability.TOOL, Capability.CREDENTIAL,
                          Capability.MCP, Capability.EGRESS}),
        block_destinations=frozenset({"evil.example"}),
    )
    assert plane.activate(operator, containment, activated_at=10).outcome is Outcome.ALLOW
    point.observe(plane.snapshot, observed_at=11)

    valid = [point.authorize(principal, Capability.DIAGNOSTIC_READ, destination="case-store", now=12,
                             boundary="effect")]
    attacks = [
        point.authorize(principal, capability, destination="evil.example", now=12, boundary="effect")
        for capability in (Capability.WRITE, Capability.TOOL, Capability.CREDENTIAL, Capability.EGRESS)
    ]
    boundary = [point.authorize(principal, Capability.WRITE, destination="case-store", now=16,
                                boundary="effect")]

    stale = EnforcementPoint("stale-worker", "north", "support-7", max_staleness=5)
    stale.observe(ControlSnapshot("north", "support-7", 0, 0, Mode.ACTIVE, frozenset(), frozenset(), ()), observed_at=0)
    failures = [
        stale.authorize(principal, Capability.WRITE, destination="case-store", now=20, boundary="effect"),
        stale.authorize(principal, Capability.TOOL, destination="case-store", now=20, boundary="effect"),
    ]

    bypass = signed_command(plane, command_id="cmd:bypass", epoch=2, mode=Mode.ACTIVE,
                            restore=frozenset({Capability.WRITE}))
    recovery_receipt = plane.activate(operator, bypass, activated_at=20)
    propagation = propagation_report(plane.snapshot, {"scheduler": 10, "gateway": 11, "worker": 14}, deadline=3)
    return EvaluationReport(
        len(valid), len(attacks), len(boundary), len(failures),
        sum(item.outcome is Outcome.ALLOW for item in valid) / len(valid),
        sum(item.outcome is Outcome.ALLOW for item in attacks) / len(attacks),
        sum(item.outcome is Outcome.DENY for item in failures) / len(failures),
        1.0 if recovery_receipt.outcome is Outcome.ALLOW else 0.0,
        propagation["slo_rate"],
    )
