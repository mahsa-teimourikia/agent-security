"""Deterministic enterprise agent security architecture controls for Course 07."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import hashlib
import hmac
import json
from typing import Iterable


def digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


class Zone(str, Enum):
    EDGE = "edge"
    ORCHESTRATION = "orchestration"
    TENANT_RUNTIME = "tenant-runtime"
    DATA = "data"
    EFFECT = "effect"
    PROTOCOL = "protocol"
    CONTROL = "control"
    OBSERVABILITY = "observability"


class DecisionState(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Component:
    component_id: str
    zone: Zone
    owner: str
    tenant_mode: str
    critical: bool
    replicas: int
    failure_domains: tuple[str, ...]
    independently_operable: bool = False


@dataclass(frozen=True)
class Flow:
    flow_id: str
    source: str
    target: str
    capability: str
    data_class: str
    authority_change: bool
    controls: frozenset[str]
    owner: str
    fail_mode: str


@dataclass(frozen=True)
class ResidualRisk:
    risk_id: str
    flow_id: str
    owner: str
    status: str
    expires_at: int
    evidence_id: str


@dataclass(frozen=True)
class Architecture:
    architecture_id: str
    version: int
    policy_version: str
    components: tuple[Component, ...]
    flows: tuple[Flow, ...]
    residual_risks: tuple[ResidualRisk, ...]


@dataclass(frozen=True)
class ArchitectureReport:
    architecture_id: str
    version: int
    required_control_slots: int
    present_control_slots: int
    control_coverage: float
    owned_objects: int
    total_owned_objects: int
    owner_coverage: float
    unmediated_paths: tuple[str, ...]
    single_points_of_failure: tuple[str, ...]
    open_residual_risks: tuple[str, ...]
    expired_residual_risks: tuple[str, ...]
    release_ready: bool


BASE_CONTROLS = frozenset({
    "workload-identity", "tenant-bind", "policy-enforcement", "evidence-receipt"
})


def required_controls(flow: Flow, components: dict[str, Component]) -> frozenset[str]:
    if not flow.authority_change:
        return frozenset()
    required = set(BASE_CONTROLS)
    source, target = components[flow.source], components[flow.target]
    if source.zone is not target.zone:
        required.add("transport-security")
    if target.zone is Zone.DATA:
        required.add("data-authorization")
    if target.zone in {Zone.EFFECT, Zone.PROTOCOL}:
        required.add("egress-control")
    return frozenset(required)


def evaluate_architecture(architecture: Architecture, now: int) -> ArchitectureReport:
    components = {item.component_id: item for item in architecture.components}
    if len(components) != len(architecture.components):
        raise ValueError("duplicate-component")
    if len({item.flow_id for item in architecture.flows}) != len(architecture.flows):
        raise ValueError("duplicate-flow")

    required_slots = 0
    present_slots = 0
    unmediated: list[str] = []
    for flow in architecture.flows:
        if flow.source not in components or flow.target not in components:
            raise ValueError(f"unknown-endpoint:{flow.flow_id}")
        required = required_controls(flow, components)
        required_slots += len(required)
        present_slots += len(required & flow.controls)
        if required - flow.controls:
            unmediated.append(flow.flow_id)
        if flow.authority_change and flow.fail_mode != "closed":
            unmediated.append(flow.flow_id)

    owned = [item for item in (*architecture.components, *architecture.flows, *architecture.residual_risks) if item.owner]
    total_owned = len(architecture.components) + len(architecture.flows) + len(architecture.residual_risks)
    spofs = sorted(
        item.component_id for item in architecture.components
        if item.critical and (item.replicas < 2 or len(set(item.failure_domains)) < 2)
    )
    open_risks = sorted(item.risk_id for item in architecture.residual_risks if item.status == "open")
    expired = sorted(
        item.risk_id for item in architecture.residual_risks
        if item.status == "accepted" and item.expires_at <= now
    )
    control_coverage = present_slots / required_slots if required_slots else 1.0
    owner_coverage = len(owned) / total_owned if total_owned else 1.0
    unmediated_paths = tuple(sorted(set(unmediated)))
    release_ready = (
        control_coverage == 1.0 and owner_coverage == 1.0 and not unmediated_paths
        and not spofs and not open_risks and not expired
    )
    return ArchitectureReport(
        architecture.architecture_id, architecture.version, required_slots, present_slots,
        control_coverage, len(owned), total_owned, owner_coverage, unmediated_paths,
        tuple(spofs), tuple(open_risks), tuple(expired), release_ready)


@dataclass(frozen=True)
class PolicySnapshot:
    version: str
    grants: frozenset[tuple[str, str, str]]
    expires_at: int
    available: bool = True


@dataclass(frozen=True)
class AccessRequest:
    request_id: str
    flow_id: str
    authenticated_principal: str
    authenticated_tenant: str
    resource_tenant: str
    capability: str
    resource_id: str
    proposal_digest: str
    policy_version: str


@dataclass(frozen=True)
class DecisionReceipt:
    request_id: str
    flow_id: str
    principal: str
    tenant: str
    capability: str
    resource_id: str
    architecture_version: int
    policy_version: str
    state: DecisionState
    reason: str
    evaluated_at: int
    proof: str = ""


class EffectGateway:
    """Trusted boundary: identity and scope come from authenticated state."""

    def __init__(self, architecture: Architecture, policy: PolicySnapshot, receipt_key: bytes):
        self.architecture = architecture
        self.policy = policy
        self.receipt_key = receipt_key

    def _sign(self, receipt: DecisionReceipt) -> DecisionReceipt:
        payload = {key: value for key, value in asdict(receipt).items() if key != "proof"}
        proof = hmac.new(self.receipt_key, digest(payload).encode(), hashlib.sha256).hexdigest()
        return replace(receipt, proof=proof)

    def decide(self, request: AccessRequest, now: int) -> DecisionReceipt:
        state, reason = DecisionState.DENY, "denied"
        flows = {item.flow_id: item for item in self.architecture.flows}
        flow = flows.get(request.flow_id)
        if flow is None:
            reason = "unknown-flow"
        elif not self.policy.available:
            state, reason = DecisionState.UNKNOWN, "policy-unavailable"
        elif self.policy.expires_at <= now or request.policy_version != self.policy.version:
            reason = "stale-policy"
        elif request.authenticated_tenant != request.resource_tenant:
            reason = "cross-tenant"
        elif request.capability != flow.capability:
            reason = "capability-mismatch"
        elif not request.proposal_digest:
            reason = "missing-proposal-digest"
        elif flow.authority_change and flow.fail_mode != "closed":
            reason = "unsafe-fail-mode"
        elif required_controls(flow, {item.component_id: item for item in self.architecture.components}) - flow.controls:
            reason = "unmediated-path"
        elif (request.authenticated_principal, request.authenticated_tenant, request.capability) not in self.policy.grants:
            reason = "not-granted"
        else:
            state, reason = DecisionState.ALLOW, "authorized"
        receipt = DecisionReceipt(
            request.request_id, request.flow_id, request.authenticated_principal,
            request.authenticated_tenant, request.capability, request.resource_id,
            self.architecture.version, self.policy.version, state, reason, now)
        return self._sign(receipt)

    def verify(self, receipt: DecisionReceipt) -> bool:
        expected = self._sign(replace(receipt, proof="")).proof
        return hmac.compare_digest(expected, receipt.proof)
