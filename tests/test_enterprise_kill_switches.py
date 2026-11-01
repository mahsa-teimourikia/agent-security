"""Focused security regression tests for Enterprise 02."""
from dataclasses import replace
from pathlib import Path
import sys
import unittest


COURSE = Path(__file__).parents[1] / "curriculum/roadmap/enterprise/02-kill-switches-revocation-and-safe-degradation"
sys.path.insert(0, str(COURSE))

import kill_switches as ks  # noqa: E402
import openfeature_adapter  # noqa: E402


class KillSwitchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plane, self.operator, self.principal, self.point = ks.build_system()

    def containment(self):
        return ks.signed_command(
            self.plane, command_id="cmd:contain", epoch=1, mode=ks.Mode.READ_ONLY,
            revoke=frozenset({ks.Capability.WRITE, ks.Capability.TOOL, ks.Capability.CREDENTIAL,
                              ks.Capability.MCP, ks.Capability.EGRESS}),
            block_destinations=frozenset({"evil.example"}),
        )

    def test_valid_signed_command_activates_once(self):
        command = self.containment()
        first = self.plane.activate(self.operator, command, activated_at=10)
        second = self.plane.activate(self.operator, command, activated_at=99)
        self.assertEqual(first, second)
        self.assertEqual(self.plane.snapshot.epoch, 1)
        self.assertEqual(self.plane.snapshot.mode, ks.Mode.READ_ONLY)

    def test_tampered_command_is_denied(self):
        command = replace(self.containment(), mode=ks.Mode.STOPPED)
        receipt = self.plane.activate(self.operator, command, activated_at=10)
        self.assertEqual(receipt.reason, "invalid-command-signature")
        self.assertEqual(self.plane.snapshot.epoch, 0)

    def test_unauthenticated_and_wrong_role_operators_are_denied(self):
        command = self.containment()
        unauthenticated = replace(self.operator, authenticated=False)
        self.assertEqual(self.plane.activate(unauthenticated, command, activated_at=10).reason,
                         "operator-not-authenticated")
        other = replace(self.operator, roles=frozenset({"viewer"}))
        self.assertEqual(self.plane.activate(other, command, activated_at=10).reason,
                         "incident-commander-required")

    def test_epoch_skips_and_replays_are_denied(self):
        skipped = ks.signed_command(self.plane, command_id="cmd:skip", epoch=2,
                                    mode=ks.Mode.STOPPED)
        self.assertEqual(self.plane.activate(self.operator, skipped, activated_at=10).reason,
                         "non-monotonic-epoch")
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        replay = ks.signed_command(self.plane, command_id="cmd:replay", epoch=1,
                                   mode=ks.Mode.STOPPED)
        self.assertEqual(self.plane.activate(self.operator, replay, activated_at=11).reason,
                         "non-monotonic-epoch")

    def test_out_of_order_snapshot_is_rejected(self):
        old = self.point.snapshot
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        self.assertTrue(self.point.observe(self.plane.snapshot, observed_at=11))
        self.assertFalse(self.point.observe(old, observed_at=12))
        self.assertEqual(self.point.snapshot.epoch, 1)

    def test_same_epoch_conflict_is_rejected(self):
        snapshot = self.point.snapshot
        conflict = replace(snapshot, mode=ks.Mode.STOPPED)
        self.assertFalse(self.point.observe(conflict, observed_at=1))

    def test_same_epoch_replay_does_not_refresh_freshness(self):
        snapshot = self.point.snapshot
        self.assertTrue(self.point.observe(snapshot, observed_at=99))
        self.assertEqual(self.point.observed_at, 0)
        result = self.point.authorize(self.principal, ks.Capability.WRITE,
                                      destination="case-store", now=6, boundary="effect")
        self.assertEqual(result.reason, "control-snapshot-stale")

    def test_schedule_and_effect_boundaries_enforce_revocation(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        self.point.observe(self.plane.snapshot, observed_at=11)
        for boundary in ("schedule", "effect"):
            result = self.point.authorize(self.principal, ks.Capability.WRITE,
                                          destination="case-store", now=12, boundary=boundary)
            self.assertEqual(result.outcome, ks.Outcome.DENY)

    def test_read_only_retains_authorized_diagnostics(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        self.point.observe(self.plane.snapshot, observed_at=11)
        result = self.point.authorize(self.principal, ks.Capability.DIAGNOSTIC_READ,
                                      destination="case-store", now=12, boundary="effect")
        self.assertEqual(result.outcome, ks.Outcome.ALLOW)

    def test_diagnostic_mode_does_not_bypass_identity_tenant_scope_or_policy(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        self.point.observe(self.plane.snapshot, observed_at=11)
        cases = [
            (replace(self.principal, authenticated=False), True),
            (replace(self.principal, tenant="south"), True),
            (replace(self.principal, scopes=frozenset()), True),
            (self.principal, False),
        ]
        for principal, current_policy in cases:
            with self.subTest(principal=principal, current_policy=current_policy):
                result = self.point.authorize(principal, ks.Capability.DIAGNOSTIC_READ,
                                              destination="case-store", now=12, boundary="effect",
                                              current_policy=current_policy)
                self.assertEqual(result.outcome, ks.Outcome.DENY)

    def test_stale_or_missing_control_denies_consequential_work(self):
        missing = ks.EnforcementPoint("missing", "north", "support-7")
        self.assertEqual(missing.authorize(self.principal, ks.Capability.WRITE,
                                          destination="case-store", now=1, boundary="effect").reason,
                         "control-snapshot-missing")
        self.assertEqual(self.point.authorize(self.principal, ks.Capability.WRITE,
                                             destination="case-store", now=6, boundary="effect").reason,
                         "control-snapshot-stale")

    def test_destination_block_is_independent_of_capability(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        self.point.observe(self.plane.snapshot, observed_at=11)
        result = self.point.authorize(self.principal, ks.Capability.DIAGNOSTIC_READ,
                                      destination="evil.example", now=12, boundary="effect")
        self.assertEqual(result.reason, "destination-blocked")

    def test_committed_effect_is_not_rolled_back(self):
        provider = ks.SyntheticProvider(supports_cancel=True)
        record = provider.dispatch(ks.EffectRecord("op:1", ks.Capability.WRITE, "crm", 9), commit=True)
        provider.contain(record)
        self.assertEqual(record.state, ks.EffectState.COMMITTED)

    def test_non_cancelable_in_flight_effect_becomes_unknown_then_reconciles(self):
        provider = ks.SyntheticProvider(supports_cancel=False)
        record = provider.dispatch(ks.EffectRecord("op:2", ks.Capability.WRITE, "crm", 9))
        provider.contain(record)
        self.assertEqual(record.state, ks.EffectState.UNKNOWN)
        provider.reconcile(record)
        self.assertEqual(record.state, ks.EffectState.CANCELED)

    def test_cancelable_in_flight_effect_is_canceled(self):
        provider = ks.SyntheticProvider(supports_cancel=True)
        record = provider.dispatch(ks.EffectRecord("op:3", ks.Capability.WRITE, "crm", 9))
        self.assertEqual(provider.contain(record).state, ks.EffectState.CANCELED)

    def test_recovery_requires_separate_fresh_bound_plan(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        bypass = ks.signed_command(self.plane, command_id="cmd:bypass", epoch=2,
                                   mode=ks.Mode.ACTIVE, restore=frozenset({ks.Capability.WRITE}))
        self.assertEqual(self.plane.activate(self.operator, bypass, activated_at=20).reason,
                         "fresh-recovery-plan-required")

        approver = ks.Operator("risk:north:2", "north", frozenset({"recovery_approver"}))
        plan = ks.RecoveryPlan("plan:1", "incident-2026-104", "north", "support-7",
                               1, 2, approver.subject, 30)
        self.plane.approve_recovery(plan, approver)
        recovery = ks.signed_command(self.plane, command_id="cmd:recover", epoch=2,
                                     mode=ks.Mode.ACTIVE, restore=frozenset({ks.Capability.WRITE}),
                                     recovery_plan_id=plan.plan_id)
        self.assertEqual(self.plane.activate(self.operator, recovery, activated_at=20).outcome,
                         ks.Outcome.ALLOW)
        self.assertNotIn(ks.Capability.WRITE, self.plane.snapshot.revoked)

    def test_recovery_plan_is_single_use(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        approver = ks.Operator("risk:north:2", "north", frozenset({"recovery_approver"}))
        plan = ks.RecoveryPlan("plan:1", "incident-2026-104", "north", "support-7", 1, 2,
                               approver.subject, 30)
        self.plane.approve_recovery(plan, approver)
        recovery = ks.signed_command(self.plane, command_id="cmd:recover", epoch=2,
                                     mode=ks.Mode.ACTIVE, restore=frozenset({ks.Capability.WRITE}),
                                     recovery_plan_id="plan:1")
        self.plane.activate(self.operator, recovery, activated_at=20)
        replay = replace(recovery, command_id="cmd:recover-again", epoch=3)
        replay = self.plane.signer.sign(replay)
        self.assertEqual(self.plane.activate(self.operator, replay, activated_at=21).reason,
                         "fresh-recovery-plan-required")

    def test_recovery_approver_must_differ_from_incident_commander(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        dual_role = replace(self.operator, roles=frozenset({"incident_commander", "recovery_approver"}))
        plan = ks.RecoveryPlan("plan:self", "incident-2026-104", "north", "support-7",
                               1, 2, dual_role.subject, 30)
        self.plane.approve_recovery(plan, dual_role)
        command = ks.signed_command(self.plane, command_id="cmd:self-recover", epoch=2,
                                    mode=ks.Mode.ACTIVE, restore=frozenset({ks.Capability.WRITE}),
                                    recovery_plan_id=plan.plan_id)
        self.assertEqual(self.plane.activate(dual_role, command, activated_at=20).reason,
                         "recovery-separation-required")

    def test_propagation_report_uses_exact_denominator(self):
        self.plane.activate(self.operator, self.containment(), activated_at=10)
        report = ks.propagation_report(self.plane.snapshot,
                                       {"scheduler": 10, "gateway": 12, "worker": 15}, deadline=3)
        self.assertEqual(report["within_slo"], 2)
        self.assertEqual(report["expected"], 3)
        self.assertAlmostEqual(report["slo_rate"], 2 / 3)

    def test_propagation_report_rejects_pre_activation_observation(self):
        snapshot = replace(self.plane.snapshot, activated_at=10)
        with self.assertRaisesRegex(ValueError, "observation-before"):
            ks.propagation_report(snapshot, {"worker": 9}, deadline=3)

    def test_evaluation_has_declared_populations_and_zero_unsafe_rate(self):
        report = ks.evaluate_controls()
        self.assertEqual((report.valid_cases, report.attack_cases, report.boundary_cases,
                          report.failure_cases), (1, 4, 1, 2))
        self.assertEqual(report.valid_diagnostic_retention_rate, 1)
        self.assertEqual(report.unsafe_effect_rate, 0)
        self.assertEqual(report.stale_snapshot_safe_denial_rate, 1)
        self.assertEqual(report.recovery_bypass_rate, 0)

    def test_real_openfeature_adapter_preserves_application_boundary(self):
        proof = openfeature_adapter.run_demo()
        self.assertFalse(proof["writes_enabled"])
        self.assertTrue(proof["diagnostics_enabled"])
        self.assertEqual(proof["epoch_from_trusted_envelope"], 7)
        self.assertFalse(proof["sdk_is_security_authority"])


if __name__ == "__main__":
    unittest.main()
