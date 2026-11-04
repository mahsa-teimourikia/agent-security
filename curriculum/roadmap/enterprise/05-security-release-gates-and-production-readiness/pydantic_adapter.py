"""Pydantic v2 adapter for hostile release-evidence payloads.

Pydantic proves only that an input conforms to this local schema. The trusted
release gate must still authenticate the producer, bind the exact artifact,
apply current policy, and decide whether production authority exists.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import hmac
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, ValidationError

import release_readiness as rr


class EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: StrictStr = Field(min_length=1)
    release_digest: StrictStr = Field(min_length=8)
    tenant: StrictStr = Field(min_length=1)
    environment: StrictStr = Field(min_length=1)
    kind: rr.EvidenceKind
    producer_id: StrictStr = Field(min_length=1)
    policy_version: StrictStr = Field(min_length=1)
    issued_at: StrictInt
    expires_at: StrictInt
    result: rr.EvidenceResult
    checked: StrictInt = Field(ge=1)
    passed: StrictInt = Field(ge=0)
    severe_failures: StrictInt = Field(ge=0)
    owner: StrictStr = Field(min_length=1)
    source_uri: StrictStr = Field(min_length=1)
    payload_digest: StrictStr = Field(min_length=8)
    key_id: StrictStr = Field(min_length=1)
    proof: StrictStr = Field(min_length=1)


def parse_evidence(payload: dict[str, Any]) -> rr.ReleaseEvidence:
    model = EvidenceModel.model_validate(payload)
    return rr.ReleaseEvidence(**model.model_dump())


class FixtureHMACKeyring:
    """Deterministic course fixture; use KMS/HSM-backed signing in production."""

    def __init__(self, secrets: dict[str, bytes]):
        self._secrets = secrets

    @staticmethod
    def _encoded(payload: dict[str, Any]) -> bytes:
        return json.dumps(rr.canonical(payload), sort_keys=True, separators=(",", ":")).encode()

    def sign(self, key_id: str, payload: dict[str, Any]) -> str:
        return hmac.new(self._secrets[key_id], self._encoded(payload), sha256).hexdigest()

    def verify(self, key_id: str, payload: dict[str, Any], proof: str) -> bool:
        secret = self._secrets.get(key_id)
        if not secret:
            return False
        expected = hmac.new(secret, self._encoded(payload), sha256).hexdigest()
        return hmac.compare_digest(expected, proof)

    def sign_evidence(self, item: rr.ReleaseEvidence, key_id: str) -> rr.ReleaseEvidence:
        unsigned = replace(item, key_id=key_id, proof="")
        return replace(unsigned, proof=self.sign(key_id, rr.evidence_payload(unsigned)))

    def sign_exception(self, item: rr.RiskException, key_id: str) -> rr.RiskException:
        unsigned = replace(item, key_id=key_id, proof="")
        return replace(unsigned, proof=self.sign(key_id, rr.exception_payload(unsigned)))

    def sign_approval(self, item: rr.ReleaseApproval, key_id: str) -> rr.ReleaseApproval:
        unsigned = replace(item, key_id=key_id, proof="")
        return replace(unsigned, proof=self.sign(key_id, rr.approval_payload(unsigned)))


def fixture_keyring() -> FixtureHMACKeyring:
    return FixtureHMACKeyring({
        "ci-evidence-2026-11": b"public-course-ci-fixture-not-a-production-secret",
        "risk-committee-2026-11": b"public-course-risk-fixture-not-a-production-secret",
        "release-board-2026-11": b"public-course-release-fixture-not-a-production-secret",
    })


__all__ = ["EvidenceModel", "FixtureHMACKeyring", "ValidationError", "fixture_keyring", "parse_evidence"]
