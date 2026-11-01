"""Credential-free OpenAI Agents SDK bridge for Enterprise 01.

The SDK owns agent-loop state.  The course control plane owns whether a stored
state may be restored now.  No model call, API key, network call, or external
side effect is used.
"""
from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass, field
from importlib.metadata import version
import json
from typing import Any

from agents import Agent, RunContextWrapper, RunState

import secure_long_running_agents as control


@dataclass(frozen=True)
class VaultEntry:
    blob_id: str
    payload: dict[str, Any]
    payload_digest: str


@dataclass
class StateVault:
    """Teaching analogue for tenant-scoped encrypted state storage."""

    entries: dict[str, VaultEntry] = field(default_factory=dict)

    def put(self, payload: dict[str, Any]) -> VaultEntry:
        payload_digest = control.canonical_digest(payload)
        entry = VaultEntry(f"run-state:{payload_digest[:20]}", deepcopy(payload), payload_digest)
        self.entries[entry.blob_id] = entry
        return entry

    def get_verified(self, blob_id: str, expected_digest: str) -> dict[str, Any]:
        entry = self.entries.get(blob_id)
        if entry is None or entry.payload_digest != expected_digest:
            raise PermissionError("run-state-missing-or-mismatched")
        if control.canonical_digest(entry.payload) != expected_digest:
            raise PermissionError("run-state-integrity")
        return deepcopy(entry.payload)


def build_agent() -> Agent[dict[str, Any]]:
    return Agent[dict[str, Any]](
        name="Long-running case agent",
        instructions=(
            "Propose case work. Application code owns identity, current authority, "
            "leases, approvals, effects, and verification."
        ),
    )


def serialize_state(agent: Agent[dict[str, Any]]) -> dict[str, Any]:
    wrapper = RunContextWrapper(
        context={
            "run_id": "run:north:42",
            "tenant": "north",
            "purpose": "case-resolution",
            "note": "synthetic; credentials never belong in agent context",
        }
    )
    state = RunState(
        context=wrapper,
        original_input="Continue the documented case after external evidence arrives.",
        starting_agent=agent,
        max_turns=6,
    )
    return state.to_json(strict_context=True)


async def restore_after_current_lease(
    agent: Agent[dict[str, Any]],
    vault: StateVault,
    resume: control.Result,
    blob_id: str,
    blob_digest: str,
) -> RunState[Any, Agent[Any]]:
    if resume.decision not in {control.Decision.ALLOW, control.Decision.IDEMPOTENT}:
        raise PermissionError("current-authority-lease-required")
    payload = vault.get_verified(blob_id, blob_digest)
    return await RunState.from_json(agent, payload, strict_context=True)


async def run_demo_async() -> dict[str, Any]:
    agent = build_agent()
    payload = serialize_state(agent)
    vault = StateVault()
    entry = vault.put(payload)

    plane, actor, _ = control.build_system()
    # The durable state reference is server-owned.  It is not treated as an
    # authorization claim, and restoration occurs only after resume succeeds.
    checkpoint = plane.runs["run:north:42"].checkpoint
    state = dict(checkpoint.state)
    state.update({"sdk_blob_id": entry.blob_id, "sdk_blob_digest": entry.payload_digest})
    plane.runs["run:north:42"].checkpoint = plane.signer.seal(
        control.replace(
            checkpoint,
            state=state,
            state_digest=control.canonical_digest(state),
            signature="",
        )
    )
    resumed = plane.resume(
        actor,
        "run:north:42",
        resume_request_id="sdk-resume:1",
        expected_version=1,
        now=control.NOW,
    )
    restored = await restore_after_current_lease(
        agent, vault, resumed, entry.blob_id, entry.payload_digest
    )

    tampered = deepcopy(entry.payload)
    tampered["max_turns"] = 999
    vault.entries[entry.blob_id] = VaultEntry(entry.blob_id, tampered, entry.payload_digest)
    tamper_rejected = False
    try:
        await restore_after_current_lease(agent, vault, resumed, entry.blob_id, entry.payload_digest)
    except PermissionError:
        tamper_rejected = True

    return {
        "sdk_version": version("openai-agents"),
        "schema_version": payload["$schemaVersion"],
        "resume_decision": resumed.decision.value,
        "lease_policy_version": resumed.lease.policy_version,
        "checkpoint_policy_version": checkpoint.policy_version,
        "state_restored_after_gate": restored._context.context["run_id"] == "run:north:42",
        "tampered_state_rejected": tamper_rejected,
        "contains_credentials": any(
            marker in json.dumps(payload).lower()
            for marker in ("api_key", "authorization: bearer", "sk-")
        ),
    }


def run_demo() -> dict[str, Any]:
    return asyncio.run(run_demo_async())


if __name__ == "__main__":
    proof = run_demo()
    assert proof["resume_decision"] == "allow"
    assert proof["lease_policy_version"] != proof["checkpoint_policy_version"]
    assert proof["state_restored_after_gate"]
    assert proof["tampered_state_rejected"]
    assert not proof["contains_credentials"]
    print(json.dumps(proof, indent=2, sort_keys=True))
