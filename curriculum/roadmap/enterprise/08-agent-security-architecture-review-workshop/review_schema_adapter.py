"""Strict Pydantic v2 adapter for untrusted architecture-review packets."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr, field_validator

import architecture_review as core


class AssetPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    asset_id: StrictStr
    tenant: StrictStr
    owner: StrictStr
    criticality: StrictStr


class EvidencePayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    evidence_id: StrictStr
    tenant: StrictStr
    subject_id: StrictStr
    kind: StrictStr
    producer: StrictStr
    source_version: StrictInt
    observed_at: StrictInt
    expires_at: StrictInt
    digest: StrictStr
    authenticated: StrictBool


class FlowPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    flow_id: StrictStr
    tenant: StrictStr
    source: StrictStr
    target: StrictStr
    capability: StrictStr
    authority_change: StrictBool
    effect: StrictBool
    owner: StrictStr
    fail_mode: StrictStr
    controls: frozenset[StrictStr]
    evidence_ids: tuple[StrictStr, ...]

    @field_validator("fail_mode")
    @classmethod
    def known_fail_mode(cls, value: str) -> str:
        if value not in {"closed", "degraded", "open"}:
            raise ValueError("unknown fail mode")
        return value


class DesignPacketPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    packet_id: StrictStr
    tenant: StrictStr
    version: StrictInt
    assets: tuple[AssetPayload, ...]
    flows: tuple[FlowPayload, ...]
    evidence: tuple[EvidencePayload, ...]

    @field_validator("packet_id", "tenant")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


def parse_packet(payload: dict) -> core.DesignPacket:
    parsed = DesignPacketPayload.model_validate(payload)
    return core.DesignPacket(
        packet_id=parsed.packet_id,
        tenant=parsed.tenant,
        version=parsed.version,
        assets=tuple(core.Asset(**item.model_dump()) for item in parsed.assets),
        flows=tuple(core.Flow(**item.model_dump()) for item in parsed.flows),
        evidence=tuple(core.EvidenceArtifact(**item.model_dump()) for item in parsed.evidence),
    )
