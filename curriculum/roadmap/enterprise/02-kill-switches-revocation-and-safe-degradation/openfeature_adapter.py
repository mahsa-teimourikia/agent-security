"""Real OpenFeature Python SDK adapter for the Enterprise 02 lab.

OpenFeature standardizes typed flag evaluation and provider lifecycle. It does
not authenticate incident commands, provide monotonic epochs, authorize a
tenant, or reconcile effects; those remain application responsibilities.
"""
from __future__ import annotations

from dataclasses import dataclass

from openfeature import api
from openfeature.evaluation_context import EvaluationContext
from openfeature.provider.in_memory_provider import InMemoryFlag, InMemoryProvider

import kill_switches as core


@dataclass(frozen=True)
class FlagObservation:
    key: str
    value: bool
    reason: str
    variant: str


def configure_provider(*, writes_enabled: bool, diagnostics_enabled: bool) -> None:
    """Install a credential-free provider and wait until it is ready."""
    flags = {
        "agent-writes-enabled": InMemoryFlag(
            "enabled" if writes_enabled else "disabled",
            {"enabled": True, "disabled": False},
        ),
        "diagnostic-reads-enabled": InMemoryFlag(
            "enabled" if diagnostics_enabled else "disabled",
            {"enabled": True, "disabled": False},
        ),
    }
    api.set_provider_and_wait(InMemoryProvider(flags))


def observe_flag(key: str, *, agent_id: str, tenant: str) -> FlagObservation:
    client = api.get_client("enterprise-kill-switch-course", "0.10")
    context = EvaluationContext(agent_id, {"tenant": tenant})
    # False is the fail-safe application default if the provider cannot answer.
    details = client.get_boolean_details(key, False, context)
    return FlagObservation(
        key,
        details.value,
        details.reason.value if details.reason else "UNKNOWN",
        details.variant or "",
    )


def snapshot_from_flags(*, trusted_epoch: int, activated_at: int,
                        tenant: str = "north", agent_id: str = "support-7") -> core.ControlSnapshot:
    """Map evaluated values into a snapshot using trusted envelope metadata.

    The flag context cannot choose tenant, agent, epoch, or activation time.
    A production adapter would accept those from an authenticated distribution
    envelope and verify them before constructing the snapshot.
    """
    writes = observe_flag("agent-writes-enabled", agent_id=agent_id, tenant=tenant)
    diagnostics = observe_flag("diagnostic-reads-enabled", agent_id=agent_id, tenant=tenant)
    revoked: set[core.Capability] = set()
    if not writes.value:
        revoked.add(core.Capability.WRITE)
    if not diagnostics.value:
        revoked.add(core.Capability.DIAGNOSTIC_READ)
    return core.ControlSnapshot(
        tenant, agent_id, trusted_epoch, activated_at,
        core.Mode.READ_ONLY if not writes.value else core.Mode.ACTIVE,
        frozenset(revoked), frozenset(), ("openfeature-observation",),
    )


def run_demo() -> dict[str, object]:
    configure_provider(writes_enabled=False, diagnostics_enabled=True)
    writes = observe_flag("agent-writes-enabled", agent_id="support-7", tenant="north")
    diagnostics = observe_flag("diagnostic-reads-enabled", agent_id="support-7", tenant="north")
    snapshot = snapshot_from_flags(trusted_epoch=7, activated_at=70)
    return {
        "sdk": "OpenFeature Python SDK",
        "writes_enabled": writes.value,
        "diagnostics_enabled": diagnostics.value,
        "write_reason": writes.reason,
        "epoch_from_trusted_envelope": snapshot.epoch,
        "mode": snapshot.mode.value,
        "sdk_is_security_authority": False,
    }


if __name__ == "__main__":
    print(run_demo())
