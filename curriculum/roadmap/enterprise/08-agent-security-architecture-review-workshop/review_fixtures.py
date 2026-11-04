"""Synthetic design packets and labels for Enterprise Course 08."""
from __future__ import annotations

from dataclasses import replace

import architecture_review as review


NOW = 10_000
RECEIPT_KEY = b"course-08-local-fixture-key"
AUTH = review.AUTHORITY_CONTROLS
EFFECT = review.EFFECT_CONTROLS


def _evidence(
    evidence_id: str,
    subject_id: str,
    *,
    version: int = 3,
    tenant: str = "north",
    kind: str = "control-test",
    observed_at: int = 9_900,
    expires_at: int = 10_500,
    authenticated: bool = True,
) -> review.EvidenceArtifact:
    return review.EvidenceArtifact(
        evidence_id=evidence_id,
        tenant=tenant,
        subject_id=subject_id,
        kind=kind,
        producer="security-ci",
        source_version=version,
        observed_at=observed_at,
        expires_at=expires_at,
        digest=f"sha256:{evidence_id}",
        authenticated=authenticated,
    )


def flawed_packet() -> review.DesignPacket:
    assets = (
        review.Asset("tenant-runtime", "north", "agent-platform", "high"),
        review.Asset("data-gateway", "north", "data-security", "high"),
        review.Asset("effect-gateway", "north", "product-security", "critical"),
        review.Asset("protocol-bridge", "north", "integration-security", "critical"),
        review.Asset("crm-north", "north", "support-operations", "critical"),
        review.Asset("crm-south", "south", "support-operations", "critical"),
    )
    flows = (
        review.Flow(
            "safe-read", "north", "tenant-runtime", "data-gateway", "customer.read",
            True, False, "data-security", "closed", AUTH,
            ("evidence:safe-read",),
        ),
        review.Flow(
            "direct-refund", "north", "tenant-runtime", "effect-gateway", "refund.issue",
            True, True, "product-security", "closed",
            AUTH - {"tenant-bind"} | {"egress-control"},
            ("evidence:direct-refund",),
        ),
        review.Flow(
            "encoded-export", "north", "protocol-bridge", "effect-gateway", "b64:export.customer",
            True, True, "", "open", AUTH,
            ("evidence:encoded-export:stale",),
        ),
        review.Flow(
            "cross-tenant-update", "north", "tenant-runtime", "crm-south", "ticket.update",
            True, True, "support-operations", "closed", AUTH | EFFECT,
            ("evidence:cross-tenant-update",),
        ),
    )
    evidence = (
        _evidence("evidence:safe-read", "safe-read"),
        _evidence("evidence:direct-refund", "direct-refund"),
        _evidence(
            "evidence:encoded-export:stale", "encoded-export",
            version=2, expires_at=9_500,
        ),
        _evidence("evidence:cross-tenant-update", "cross-tenant-update"),
    )
    return review.DesignPacket("support-agent-review", "north", 3, assets, flows, evidence)


def remediated_packet() -> review.DesignPacket:
    before = flawed_packet()
    assets = tuple(item for item in before.assets if item.asset_id != "crm-south")
    flows = (
        replace(before.flows[0]),
        replace(before.flows[1], controls=AUTH | EFFECT),
        replace(
            before.flows[2], owner="integration-security", fail_mode="closed",
            controls=AUTH | EFFECT,
        ),
        replace(before.flows[3], target="crm-north"),
    )
    evidence = tuple(
        _evidence(f"evidence:{flow.flow_id}:v4", flow.flow_id, version=4)
        for flow in flows
    )
    flows = tuple(
        replace(flow, evidence_ids=(f"evidence:{flow.flow_id}:v4",))
        for flow in flows
    )
    return review.DesignPacket(before.packet_id, before.tenant, 4, assets, flows, evidence)


def service(*, evidence_available: bool = True) -> review.ReviewService:
    return review.ReviewService(
        RECEIPT_KEY,
        authenticated_tenant="north",
        review_owner="security-architecture",
        evidence_available=evidence_available,
    )


def expected_keys() -> frozenset[str]:
    """Human-labelled answer key; intentionally independent of review()."""
    return frozenset({
        "INV-AUTHORITY-MEDIATION:direct-refund",
        "INV-EFFECT-BOUNDARY:direct-refund",
        "INV-EFFECT-BOUNDARY:encoded-export",
        "INV-FAIL-CLOSED:encoded-export",
        "INV-ACCOUNTABLE-OWNER:encoded-export",
        "INV-CURRENT-EVIDENCE:encoded-export",
        "INV-TENANT-SCOPE:cross-tenant-update",
    })


def severe_expected_keys() -> frozenset[str]:
    return frozenset({
        "INV-AUTHORITY-MEDIATION:direct-refund",
        "INV-EFFECT-BOUNDARY:direct-refund",
        "INV-EFFECT-BOUNDARY:encoded-export",
        "INV-TENANT-SCOPE:cross-tenant-update",
    })


def review_universe() -> frozenset[str]:
    return expected_keys() | {
        "INV-FAIL-CLOSED:direct-refund",
        "INV-CURRENT-EVIDENCE:direct-refund",
        "INV-ACCOUNTABLE-OWNER:direct-refund",
    }
