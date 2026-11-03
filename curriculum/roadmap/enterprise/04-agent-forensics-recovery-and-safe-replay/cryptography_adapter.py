"""Real ``cryptography`` Ed25519 adapter for course evidence and approvals.

The fixed private seeds are deterministic course fixtures, not production key
management. Production deployments use workload identity, HSM/KMS-backed keys,
rotation, revocation, trusted timestamps, and access-controlled evidence stores.
"""
from __future__ import annotations

from dataclasses import replace
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import forensics_recovery as fr


def encoded(payload: dict[str, Any]) -> bytes:
    return json.dumps(fr.canonical(payload), sort_keys=True, separators=(",", ":")).encode()


class Ed25519Keyring:
    def __init__(self, private_seeds: dict[str, bytes]):
        self._private = {
            key_id: Ed25519PrivateKey.from_private_bytes(seed)
            for key_id, seed in private_seeds.items()
        }
        self._public: dict[str, Ed25519PublicKey] = {
            key_id: private_key.public_key()
            for key_id, private_key in self._private.items()
        }

    def sign(self, key_id: str, payload: dict[str, Any]) -> str:
        return self._private[key_id].sign(encoded(payload)).hex()

    def verify(self, key_id: str, payload: dict[str, Any], signature: str) -> bool:
        public_key = self._public.get(key_id)
        if not public_key:
            return False
        try:
            public_key.verify(bytes.fromhex(signature), encoded(payload))
        except (InvalidSignature, ValueError):
            return False
        return True

    def public_key_hex(self, key_id: str) -> str:
        return self._public[key_id].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()

    def sign_event(self, event: fr.ForensicEvent, key_id: str) -> fr.ForensicEvent:
        unsigned = replace(event, key_id=key_id, signature="")
        return replace(unsigned, signature=self.sign(key_id, fr.event_payload(unsigned)))

    def sign_checkpoint(self, checkpoint: fr.CheckpointManifest, key_id: str) -> fr.CheckpointManifest:
        unsigned = replace(checkpoint, key_id=key_id, signature="")
        return replace(unsigned, signature=self.sign(key_id, fr.checkpoint_payload(unsigned)))

    def sign_approval(self, approval: fr.RecoveryApproval, key_id: str) -> fr.RecoveryApproval:
        unsigned = replace(approval, key_id=key_id, signature="")
        return replace(unsigned, signature=self.sign(key_id, fr.approval_payload(unsigned)))


def course_keyring() -> Ed25519Keyring:
    return Ed25519Keyring({
        "runtime-evidence-2026-11": bytes.fromhex("11" * 32),
        "checkpoint-authority-2026-11": bytes.fromhex("22" * 32),
        "recovery-approval-2026-11": bytes.fromhex("33" * 32),
    })
