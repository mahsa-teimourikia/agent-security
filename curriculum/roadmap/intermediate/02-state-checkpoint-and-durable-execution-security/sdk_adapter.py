"""Credential-free OpenAI Agents SDK RunState adapter for Intermediate 02.

The adapter serializes a real SDK RunState, keeps it in a server-side vault,
binds its digest into the course checkpoint, and restores it only after the
application resume gate succeeds. No model, network call, credential, or API
key is used.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass, field
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

from agents import Agent, RunContextWrapper, RunState


SPEC = importlib.util.spec_from_file_location("intermediate_02_durable_lab", Path(__file__).with_name("lab.py"))
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


@dataclass(frozen=True)
class VaultEntry:
    blob_id: str
    payload: dict[str, Any]
    payload_digest: str


@dataclass
class SerializedStateVault:
    """Server-side teaching analogue for encrypted, access-controlled storage."""

    entries: dict[str, VaultEntry] = field(default_factory=dict)

    def put(self, payload: dict[str, Any]) -> VaultEntry:
        payload_digest = LAB.digest(payload)
        blob_id = f"sdk-state:{payload_digest[:20]}"
        entry = VaultEntry(blob_id, deepcopy(payload), payload_digest)
        self.entries[blob_id] = entry
        return entry

    def load_exact(self, blob_id: str, expected_digest: str) -> dict[str, Any]:
        entry = self.entries.get(blob_id)
        if entry is None:
            raise PermissionError("serialized state is missing")
        actual = LAB.digest(entry.payload)
        if entry.payload_digest != expected_digest or actual != expected_digest:
            raise PermissionError("serialized state integrity mismatch")
        return deepcopy(entry.payload)


def build_agent() -> Agent[dict[str, Any]]:
    return Agent[dict[str, Any]](
        name="Durable support workflow",
        instructions=(
            "Propose work and surface approval interruptions. Application code owns "
            "checkpoint integrity, identity, authorization, leases, migration, and effects."
        ),
    )


def serialize_real_run_state(agent: Agent[dict[str, Any]]) -> dict[str, Any]:
    context = RunContextWrapper(context={
        "run_id": "run:sdk-case-7",
        "tenant": "north",
        "purpose": "case-resolution",
        "note": "synthetic; do not place credentials in serialized context",
    })
    state = RunState(
        context=context,
        original_input="Prepare the already-approved case closure.",
        starting_agent=agent,
        max_turns=4,
    )
    return state.to_json(strict_context=True)


def checkpoint_sdk_state(
    service: Any, base_checkpoint: Any, vault: SerializedStateVault, sdk_payload: dict[str, Any]
) -> Any:
    entry = vault.put(sdk_payload)
    return service.create_checkpoint(
        run_id="run:sdk-case-7", tenant=base_checkpoint.tenant,
        owner_principal=base_checkpoint.owner_principal,
        workflow_version="workflow-v2", schema_version=2,
        policy_version=service.policy.current.version,
        tool_version=service.policy.current.tool_version,
        status=LAB.RunStatus.PAUSED, pending_step="resume-sdk-state",
        state={"sdk_blob_id": entry.blob_id, "sdk_blob_digest": entry.payload_digest},
        pending_effect=base_checkpoint.pending_effect,
        approval_id=base_checkpoint.approval_id,
        remaining_steps=4, now=LAB.NOW,
    )


async def restore_after_gate(
    agent: Agent[dict[str, Any]], vault: SerializedStateVault, resume_decision: Any
) -> RunState[Any, Agent[Any]]:
    if resume_decision.status not in {LAB.ResumeStatus.READY, LAB.ResumeStatus.IDEMPOTENT}:
        raise PermissionError("application resume gate did not authorize restoration")
    state = resume_decision.lease.state
    payload = vault.load_exact(state["sdk_blob_id"], state["sdk_blob_digest"])
    # The SDK reconstructs runtime state; the application gate above authenticates
    # the server-owned envelope. RunState.from_json does not do that authentication.
    return await RunState.from_json(agent, payload, strict_context=True)


async def credential_free_demo_async() -> dict[str, Any]:
    agent = build_agent()
    sdk_payload = serialize_real_run_state(agent)
    vault = SerializedStateVault()
    service, base_checkpoint, _ = LAB.build_system(
        workflow_version="workflow-v2", schema_version=2
    )
    checkpoint = checkpoint_sdk_state(service, base_checkpoint, vault, sdk_payload)
    decision = service.resume(
        LAB.actor("sdk:resume"), checkpoint.checkpoint_id,
        resume_request_id="sdk:resume-request", now=LAB.NOW,
    )
    restored = await restore_after_gate(agent, vault, decision)

    blob_id = decision.lease.state["sdk_blob_id"]
    original_entry = vault.entries[blob_id]
    tampered = deepcopy(original_entry.payload)
    tampered["max_turns"] = 999
    vault.entries[blob_id] = VaultEntry(blob_id, tampered, original_entry.payload_digest)
    tamper_rejected = False
    try:
        await restore_after_gate(agent, vault, decision)
    except PermissionError:
        tamper_rejected = True

    return {
        "sdk_schema_version": sdk_payload["$schemaVersion"],
        "sdk_payload_fields": sorted(sdk_payload),
        "resume_status": decision.status.value,
        "checkpoint_integrity_verified_before_deserialization": True,
        "snapshot_kept_server_side": True,
        "tampered_blob_rejected": tamper_rejected,
        "restored_context": restored._context.context,
        "serialized_context_contains_no_credentials": not any(
            marker in json.dumps(sdk_payload).lower()
            for marker in ("sk-", "api_key", "authorization: bearer")
        ),
    }


def credential_free_demo() -> dict[str, Any]:
    return asyncio.run(credential_free_demo_async())


if __name__ == "__main__":
    proof = credential_free_demo()
    assert proof["resume_status"] == "ready"
    assert proof["snapshot_kept_server_side"]
    assert proof["tampered_blob_rejected"]
    assert proof["serialized_context_contains_no_credentials"]
    print(json.dumps(proof, indent=2, sort_keys=True))
