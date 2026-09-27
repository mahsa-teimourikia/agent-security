"""Credential-free real-SDK tests for Foundation 07."""
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "beginner" / "07-context-and-evidence-security"
SPEC = importlib.util.spec_from_file_location("foundation_07_sdk_tests", COURSE / "sdk_adapter.py")
assert SPEC and SPEC.loader
SDK = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, SDK)
SPEC.loader.exec_module(SDK)


def test_real_sdk_strict_tool_is_wired_without_network() -> None:
    release, evidence = SDK.credential_free_demo()
    assert release.status is SDK.LAB.ReleaseStatus.ANSWERED
    assert evidence["tool_name"] == "read_admitted_evidence"
    assert evidence["strict_json_schema"] is True
    assert evidence["schema_fields"] == ["evidence_ref"]
    assert evidence["trusted_fields_excluded"] is True
    assert evidence["payload"]["claims"] == [{"key": "retention_days", "value": "30"}]


def test_sdk_schema_excludes_identity_policy_and_manifest_authority() -> None:
    properties = SDK.read_admitted_evidence.params_json_schema["properties"]
    assert set(properties) == {"evidence_ref"}
    assert not ({"subject", "tenant", "clearance", "purpose", "policy_version", "manifest_digest"} & set(properties))


def test_sdk_dispatch_cannot_read_a_registry_item_outside_manifest() -> None:
    registry = SDK.LAB.build_registry()
    request = SDK.LAB.request_for("retention_days")
    policy = registry.records["policy:retention"]
    manifest = SDK.LAB.ContextCompiler(registry).compile(request, (SDK.LAB.CandidateRef.exact(policy),), now=SDK.LAB.NOW)
    runtime = SDK.SDKRuntime(request, registry, manifest)
    with pytest.raises(PermissionError, match="not in the compiled manifest"):
        SDK.read_admitted(runtime, registry.records["case:unretrieved"].reference)


def test_sdk_dispatch_rejects_registry_rotation_after_manifest() -> None:
    registry = SDK.LAB.build_registry()
    request = SDK.LAB.request_for("retention_days")
    policy = registry.records["policy:retention"]
    manifest = SDK.LAB.ContextCompiler(registry).compile(request, (SDK.LAB.CandidateRef.exact(policy),), now=SDK.LAB.NOW)
    runtime = SDK.SDKRuntime(request, registry, manifest)
    registry.records[policy.source_id] = SDK.LAB.make_evidence(
        policy.source_id, policy.version + 1, policy.tenant, policy.kind, policy.classification,
        policy.authority, policy.locator, (("retention_days", "45"),), "Now 45 days.",
        SDK.LAB.NOW, SDK.LAB.NOW + SDK.LAB.timedelta(days=30),
    )
    with pytest.raises(PermissionError, match="no longer current"):
        SDK.read_admitted(runtime, policy.reference)


def test_sdk_dispatch_requires_refresh_after_registry_version_change() -> None:
    registry = SDK.LAB.build_registry()
    request = SDK.LAB.request_for("retention_days")
    policy = registry.records["policy:retention"]
    manifest = SDK.LAB.ContextCompiler(registry).compile(request, (SDK.LAB.CandidateRef.exact(policy),), now=SDK.LAB.NOW)
    runtime = SDK.SDKRuntime(request, registry, manifest)
    registry.version = "registry-2"
    with pytest.raises(PermissionError, match="requires refresh"):
        SDK.read_admitted(runtime, policy.reference)
