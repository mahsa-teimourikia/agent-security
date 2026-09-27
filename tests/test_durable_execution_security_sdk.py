"""Credential-free real-SDK tests for Intermediate 02."""
import asyncio
from copy import deepcopy
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "02-state-checkpoint-and-durable-execution-security"
SPEC = importlib.util.spec_from_file_location("intermediate_02_durable_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_run_state_round_trips_after_application_gate() -> None:
    proof = SDK.credential_free_demo()
    assert proof["sdk_schema_version"]
    assert proof["resume_status"] == "ready"
    assert proof["checkpoint_integrity_verified_before_deserialization"]
    assert proof["snapshot_kept_server_side"]
    assert proof["tampered_blob_rejected"]
    assert proof["restored_context"]["run_id"] == "run:sdk-case-7"


def test_sdk_state_uses_strict_mapping_context_without_credentials() -> None:
    proof = SDK.credential_free_demo()
    assert proof["serialized_context_contains_no_credentials"]
    assert {"context", "original_input", "current_agent", "$schemaVersion"} <= set(proof["sdk_payload_fields"])


def test_adapter_refuses_deserialization_when_application_gate_denies() -> None:
    agent = SDK.build_agent()
    vault = SDK.SerializedStateVault()
    vault.put(SDK.serialize_real_run_state(agent))
    service, checkpoint, _ = SDK.LAB.build_system(workflow_version="workflow-v2", schema_version=2)
    denied = service.resume(
        SDK.LAB.actor("sdk:cross", tenant="south"), checkpoint.checkpoint_id,
        resume_request_id="sdk:cross", now=SDK.LAB.NOW,
    )
    with pytest.raises(PermissionError, match="did not authorize"):
        asyncio.run(SDK.restore_after_gate(agent, vault, denied))


def test_vault_digest_covers_complete_sdk_snapshot() -> None:
    agent = SDK.build_agent()
    vault = SDK.SerializedStateVault()
    entry = vault.put(SDK.serialize_real_run_state(agent))
    changed = deepcopy(entry.payload)
    changed["max_turns"] = changed["max_turns"] + 1
    vault.entries[entry.blob_id] = SDK.VaultEntry(entry.blob_id, changed, entry.payload_digest)
    with pytest.raises(PermissionError, match="integrity mismatch"):
        vault.load_exact(entry.blob_id, entry.payload_digest)

