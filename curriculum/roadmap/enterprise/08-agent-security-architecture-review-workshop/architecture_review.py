"""Deterministic architecture-review controls for Enterprise Course 08.

The model or a human reviewer may propose findings. This module owns the
repeatable checks, evidence admission, disposition, and remediation proof.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass, replace
from enum import Enum
import hashlib
import hmac
import json
from typing import Iterable


def _canonical(value: object) -> object:
    if is_dataclass(value):
        return _canonical(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonical(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        items = [_canonical(item) for item in value]
        return sorted(items, key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def digest(value: object) -> str:
    encoded = json.dumps(_canonical(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Disposition(str, Enum):
    PASS = "pass"
    BLOCK = "block"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Asset:
    asset_id: str
    tenant: str
    owner: str
    criticality: str


@dataclass(frozen=True)
class EvidenceArtifact:
    evidence_id: str
    tenant: str
    subject_id: str
    kind: str
    producer: str
    source_version: int
    observed_at: int
    expires_at: int
    digest: str
    authenticated: bool


@dataclass(frozen=True)
class Flow:
    flow_id: str
    tenant: str
    source: str
    target: str
    capability: str
    authority_change: bool
    effect: bool
    owner: str
    fail_mode: str
    controls: frozenset[str]
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class DesignPacket:
    packet_id: str
    tenant: str
    version: int
    assets: tuple[Asset, ...]
    flows: tuple[Flow, ...]
    evidence: tuple[EvidenceArtifact, ...]


@dataclass(frozen=True)
class Finding:
    invariant_id: str
    flow_id: str
    severity: Severity
    attack_path: str
    affected_asset: str
    evidence_ids: tuple[str, ...]
    owner: str
    remediation: str

    @property
    def key(self) -> str:
        return f"{self.invariant_id}:{self.flow_id}"


@dataclass(frozen=True)
class ReviewReceipt:
    receipt_id: str
    packet_id: str
    packet_version: int
    packet_digest: str
    tenant: str
    review_version: str
    disposition: Disposition
    reason: str
    finding_keys: tuple[str, ...]
    evaluated_at: int
    proof: str = ""


@dataclass(frozen=True)
class ReviewResult:
    receipt: ReviewReceipt
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class RemediationOutcome:
    finding_key: str
    verified: bool
    reason: str


AUTHORITY_CONTROLS = frozenset({
    "workload-identity", "tenant-bind", "policy-enforcement", "evidence-receipt"
})
EFFECT_CONTROLS = frozenset({"effect-authorization", "egress-control", "idempotency"})


def packet_digest(packet: DesignPacket) -> str:
    """Bind a receipt to the exact packet without treating its data as trusted."""
    return digest(asdict(packet))


def evidence_is_current(
    artifact: EvidenceArtifact,
    packet: DesignPacket,
    flow: Flow,
    now: int,
) -> bool:
    return (
        artifact.authenticated
        and bool(artifact.digest)
        and artifact.tenant == packet.tenant == flow.tenant
        and artifact.subject_id == flow.flow_id
        and artifact.source_version == packet.version
        and artifact.observed_at <= now < artifact.expires_at
    )


class ReviewService:
    """Trusted review boundary for deterministic, evidence-backed findings.

    The HMAC is a credential-free teaching substitute for a production signing
    service. It proves fixture integrity only; it does not grant deployment
    authority.
    """

    def __init__(
        self,
        receipt_key: bytes,
        authenticated_tenant: str,
        review_owner: str,
        review_version: str = "review-rules-1",
        evidence_available: bool = True,
    ):
        self.receipt_key = receipt_key
        self.authenticated_tenant = authenticated_tenant
        self.review_owner = review_owner
        self.review_version = review_version
        self.evidence_available = evidence_available

    def _sign(self, receipt: ReviewReceipt) -> ReviewReceipt:
        payload = {key: value for key, value in asdict(receipt).items() if key != "proof"}
        proof = hmac.new(self.receipt_key, digest(payload).encode(), hashlib.sha256).hexdigest()
        return replace(receipt, proof=proof)

    def verify_receipt(self, receipt: ReviewReceipt) -> bool:
        expected = self._sign(replace(receipt, proof="")).proof
        return hmac.compare_digest(expected, receipt.proof)

    def _validate_structure(self, packet: DesignPacket) -> dict[str, Asset]:
        assets = {item.asset_id: item for item in packet.assets}
        if len(assets) != len(packet.assets):
            raise ValueError("duplicate-asset")
        if len({item.flow_id for item in packet.flows}) != len(packet.flows):
            raise ValueError("duplicate-flow")
        if len({item.evidence_id for item in packet.evidence}) != len(packet.evidence):
            raise ValueError("duplicate-evidence")
        for flow in packet.flows:
            if flow.source not in assets or flow.target not in assets:
                raise ValueError(f"unknown-endpoint:{flow.flow_id}")
        return assets

    def _finding(
        self,
        invariant_id: str,
        flow: Flow,
        severity: Severity,
        affected_asset: str,
        remediation: str,
    ) -> Finding:
        return Finding(
            invariant_id=invariant_id,
            flow_id=flow.flow_id,
            severity=severity,
            attack_path=f"{flow.source} -> {flow.target} ({flow.capability})",
            affected_asset=affected_asset,
            evidence_ids=flow.evidence_ids,
            owner=flow.owner or self.review_owner,
            remediation=remediation,
        )

    def review(self, packet: DesignPacket, now: int) -> ReviewResult:
        assets = self._validate_structure(packet)
        if packet.tenant != self.authenticated_tenant:
            raise ValueError("tenant-scope-mismatch")
        if not self.evidence_available:
            receipt = ReviewReceipt(
                f"review:{packet.packet_id}:{packet.version}", packet.packet_id,
                packet.version, packet_digest(packet), packet.tenant,
                self.review_version, Disposition.UNKNOWN, "evidence-dependency-unavailable",
                (), now,
            )
            return ReviewResult(self._sign(receipt), ())

        evidence = {item.evidence_id: item for item in packet.evidence}
        findings: list[Finding] = []
        for flow in packet.flows:
            target = assets[flow.target]
            if flow.tenant != packet.tenant or assets[flow.source].tenant != packet.tenant or target.tenant != packet.tenant:
                findings.append(self._finding(
                    "INV-TENANT-SCOPE", flow, Severity.CRITICAL, target.asset_id,
                    "derive tenant scope from authenticated state and enforce target ownership",
                ))

            if flow.authority_change and AUTHORITY_CONTROLS - flow.controls:
                missing = ", ".join(sorted(AUTHORITY_CONTROLS - flow.controls))
                findings.append(self._finding(
                    "INV-AUTHORITY-MEDIATION", flow, Severity.CRITICAL, target.asset_id,
                    f"mediate the path with: {missing}",
                ))

            if flow.effect and EFFECT_CONTROLS - flow.controls:
                missing = ", ".join(sorted(EFFECT_CONTROLS - flow.controls))
                findings.append(self._finding(
                    "INV-EFFECT-BOUNDARY", flow, Severity.CRITICAL, target.asset_id,
                    f"enforce the effect boundary with: {missing}",
                ))

            if flow.authority_change and flow.fail_mode != "closed":
                findings.append(self._finding(
                    "INV-FAIL-CLOSED", flow, Severity.HIGH, target.asset_id,
                    "make dependency failure explicit UNKNOWN or DENY and reconcile before retry",
                ))

            if not flow.owner:
                findings.append(self._finding(
                    "INV-ACCOUNTABLE-OWNER", flow, Severity.HIGH, target.asset_id,
                    "assign an accountable remediation and operational owner",
                ))

            admitted = [
                evidence[item]
                for item in flow.evidence_ids
                if item in evidence and evidence_is_current(evidence[item], packet, flow, now)
            ]
            if not admitted:
                findings.append(self._finding(
                    "INV-CURRENT-EVIDENCE", flow, Severity.HIGH, target.asset_id,
                    "attach producer-authenticated, tenant-bound, version-current test evidence",
                ))

        ordered = tuple(sorted(findings, key=lambda item: item.key))
        disposition = Disposition.BLOCK if ordered else Disposition.PASS
        receipt = ReviewReceipt(
            f"review:{packet.packet_id}:{packet.version}", packet.packet_id,
            packet.version, packet_digest(packet), packet.tenant,
            self.review_version, disposition,
            "actionable-findings" if ordered else "all-invariants-proven",
            tuple(item.key for item in ordered), now,
        )
        return ReviewResult(self._sign(receipt), ordered)


def diagram_only_review(packet: DesignPacket) -> tuple[str, ...]:
    """Intentionally weak baseline: checks only that diagram endpoints exist."""
    asset_ids = {item.asset_id for item in packet.assets}
    return tuple(
        sorted(flow.flow_id for flow in packet.flows if flow.source not in asset_ids or flow.target not in asset_ids)
    )


def verify_remediations(
    service: ReviewService,
    before: DesignPacket,
    after: DesignPacket,
    attempted: Iterable[Finding],
    now: int,
) -> tuple[RemediationOutcome, ...]:
    if after.packet_id != before.packet_id or after.tenant != before.tenant:
        raise ValueError("packet-identity-changed")
    if after.version <= before.version:
        raise ValueError("version-not-advanced")
    final_review = service.review(after, now)
    remaining = {item.key for item in final_review.findings}
    evidence = {item.evidence_id: item for item in after.evidence}
    flows = {item.flow_id: item for item in after.flows}
    outcomes: list[RemediationOutcome] = []
    for finding in attempted:
        flow = flows.get(finding.flow_id)
        current_tests = [] if flow is None else [
            evidence[item]
            for item in flow.evidence_ids
            if item in evidence
            and evidence[item].kind == "control-test"
            and evidence_is_current(evidence[item], after, flow, now)
        ]
        if final_review.receipt.disposition is not Disposition.PASS:
            outcomes.append(RemediationOutcome(
                finding.key, False, f"review-not-pass:{final_review.receipt.disposition.value}"
            ))
        elif finding.key in remaining:
            outcomes.append(RemediationOutcome(finding.key, False, "invariant-still-violated"))
        elif not current_tests:
            outcomes.append(RemediationOutcome(finding.key, False, "missing-current-control-test"))
        else:
            outcomes.append(RemediationOutcome(finding.key, True, "verified-by-current-control-test"))
    return tuple(outcomes)
