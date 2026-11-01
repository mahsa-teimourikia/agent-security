"""Run the complete, credential-free Enterprise 02 proof."""
from dataclasses import asdict
import json

import kill_switches as course
import openfeature_adapter


def main() -> None:
    plane, operator, principal, point = course.build_system()
    command = course.signed_command(
        plane,
        command_id="cmd:contain:1",
        epoch=1,
        mode=course.Mode.READ_ONLY,
        revoke=frozenset({
            course.Capability.WRITE,
            course.Capability.TOOL,
            course.Capability.CREDENTIAL,
            course.Capability.MCP,
            course.Capability.EGRESS,
        }),
        block_destinations=frozenset({"evil.example"}),
    )
    receipt = plane.activate(operator, command, activated_at=10)
    assert receipt.outcome is course.Outcome.ALLOW
    assert point.observe(plane.snapshot, observed_at=11)

    write = point.authorize(principal, course.Capability.WRITE,
                            destination="case-store", now=12, boundary="effect")
    diagnostic = point.authorize(principal, course.Capability.DIAGNOSTIC_READ,
                                 destination="case-store", now=12, boundary="effect")
    assert write.outcome is course.Outcome.DENY
    assert diagnostic.outcome is course.Outcome.ALLOW

    provider = course.SyntheticProvider(supports_cancel=False)
    effect = provider.dispatch(course.EffectRecord(
        "operation:42", course.Capability.WRITE, "case-store", 9,
    ))
    provider.contain(effect)
    assert effect.state is course.EffectState.UNKNOWN
    provider.reconcile(effect)
    assert effect.state is course.EffectState.CANCELED

    report = course.evaluate_controls()
    sdk = openfeature_adapter.run_demo()
    assert report.unsafe_effect_rate == 0
    assert report.stale_snapshot_safe_denial_rate == 1
    assert report.recovery_bypass_rate == 0
    assert sdk["writes_enabled"] is False and sdk["diagnostics_enabled"] is True
    print(json.dumps({
        "control_receipt": asdict(receipt),
        "write": asdict(write),
        "diagnostic": asdict(diagnostic),
        "in_flight_after_reconcile": effect.state.value,
        "evaluation": asdict(report),
        "openfeature": sdk,
    }, indent=2, default=lambda value: value.value))


if __name__ == "__main__":
    main()
