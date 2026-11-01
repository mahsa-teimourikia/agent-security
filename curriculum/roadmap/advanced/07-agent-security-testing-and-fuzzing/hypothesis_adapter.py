"""Real Hypothesis integration for Advanced 07.

Hypothesis generates and shrinks examples; the application-owned oracle in
``lab.py`` decides whether a forbidden outcome occurred.  The settings are
deterministic and disable the example database so the notebook and CI have the
same credential-free behavior.
"""
from __future__ import annotations

from dataclasses import asdict
import importlib.util
from pathlib import Path
import sys

from hypothesis import find, given, settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule, run_state_machine_as_test


LAB_NAME = "advanced_07_fuzzing_lab"
if LAB_NAME in sys.modules:
    lab = sys.modules[LAB_NAME]
else:
    LAB_SPEC = importlib.util.spec_from_file_location(LAB_NAME, Path(__file__).with_name("lab.py"))
    assert LAB_SPEC and LAB_SPEC.loader
    lab = importlib.util.module_from_spec(LAB_SPEC)
    sys.modules[LAB_NAME] = lab
    LAB_SPEC.loader.exec_module(lab)


DETERMINISTIC = settings(
    max_examples=80,
    derandomize=True,
    database=None,
    deadline=None,
)


ENCODED_EXECUTE_COMMANDS = st.sampled_from(
    (
        "EXECUTE_EXPORT",
        "execute_export ",
        "ｅxecute_export",
        "execute_exporｔ",
    )
)


@DETERMINISTIC
@given(
    claimed_tenant=st.text(max_size=24),
    claimed_subject=st.text(max_size=24),
    operation=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd")),
        min_size=1,
        max_size=24,
    ),
)
def property_untrusted_identity_never_authorizes_cross_tenant_effect(
    claimed_tenant: str,
    claimed_subject: str,
    operation: str,
) -> None:
    actor = lab.principals()["outsider"]
    item = lab.request(
        lab.Command.EXECUTE_EXPORT,
        f"property:{operation}",
        state_version=2,
        resource_id="case:north:7",
        approval_id="approval:property",
        claimed_tenant=claimed_tenant,
        claimed_subject=claimed_subject,
    )
    case = lab.FuzzCase(
        "property-cross-tenant",
        lab.CaseKind.ATTACK,
        actor,
        item,
        lab.WorkflowState.APPROVED,
        2,
        lab.DecisionStatus.DENY,
    )
    result = lab.run_case(case, lab.SecureGateway)
    assert result.receipt.status is lab.DecisionStatus.DENY
    assert not result.receipt.effect_applied
    assert not result.findings


@DETERMINISTIC
@given(
    command=st.text(min_size=0, max_size=30),
    operation_size=st.integers(min_value=0, max_value=80),
    payload_size=st.integers(min_value=-2, max_value=10_000),
)
def property_malformed_input_never_changes_secure_state(
    command: str,
    operation_size: int,
    payload_size: int,
) -> None:
    if command in {item.value for item in lab.Command}:
        return
    actor = lab.principals()["requester"]
    workflow = lab.Workflow(
        "workflow:north:7",
        "north",
        "case:north:7",
        state=lab.WorkflowState.APPROVED,
        version=2,
    )
    gateway = lab.SecureGateway(workflow, lab.resources())
    before = workflow.snapshot()
    receipt = gateway.execute(
        actor,
        lab.request(
            command,
            "x" * operation_size,
            state_version=2,
            payload_bytes=payload_size,
        ),
    )
    assert receipt.status is lab.DecisionStatus.DENY
    assert workflow.snapshot() == before


def find_unsafe_encoded_bypass() -> dict[str, object]:
    actor = lab.principals()["requester"]

    def causes_effect(command: str) -> bool:
        workflow = lab.Workflow(
            "workflow:north:7",
            "north",
            "case:north:7",
            state=lab.WorkflowState.APPROVED,
            version=2,
        )
        gateway = lab.UnsafeGateway(workflow, lab.resources())
        item = lab.request(command, "hypothesis:bypass", state_version=2)
        receipt = gateway.execute(actor, item)
        return receipt.effect_applied

    found = find(ENCODED_EXECUTE_COMMANDS, causes_effect, settings=DETERMINISTIC)
    secure_workflow = lab.Workflow(
        "workflow:north:7",
        "north",
        "case:north:7",
        state=lab.WorkflowState.APPROVED,
        version=2,
    )
    secure = lab.SecureGateway(secure_workflow, lab.resources())
    secure_receipt = secure.execute(actor, lab.request(found, "hypothesis:secure", state_version=2))
    return {
        "counterexample": found,
        "utf8_bytes": len(found.encode()),
        "code_points": len(found),
        "unsafe_effect": True,
        "secure_status": secure_receipt.status.value,
        "secure_reason": secure_receipt.reason,
    }


class SecureWorkflowMachine(RuleBasedStateMachine):
    """Generate command sequences and check invariants after every step."""

    def __init__(self) -> None:
        super().__init__()
        self.workflow = lab.Workflow("workflow:north:7", "north", "case:north:7")
        self.gateway = lab.SecureGateway(self.workflow, lab.resources())
        self.people = lab.principals()
        self.counter = 0

    def next_operation(self, prefix: str) -> str:
        self.counter += 1
        return f"stateful:{prefix}:{self.counter}"

    @precondition(lambda self: self.workflow.state is lab.WorkflowState.DRAFT)
    @rule()
    def submit(self) -> None:
        item = lab.request(
            lab.Command.SUBMIT_REVIEW,
            self.next_operation("submit"),
            state_version=self.workflow.version,
        )
        self.gateway.execute(self.people["requester"], item, step=self.counter)

    @precondition(lambda self: self.workflow.state is lab.WorkflowState.REVIEW)
    @rule()
    def approve(self) -> None:
        item = lab.request(
            lab.Command.APPROVE_EXPORT,
            self.next_operation("approve"),
            state_version=self.workflow.version,
        )
        self.gateway.execute(self.people["approver"], item, step=self.counter)

    @precondition(lambda self: self.workflow.state in {lab.WorkflowState.DRAFT, lab.WorkflowState.REVIEW, lab.WorkflowState.APPROVED})
    @rule()
    def cancel(self) -> None:
        item = lab.request(
            lab.Command.CANCEL,
            self.next_operation("cancel"),
            state_version=self.workflow.version,
        )
        self.gateway.execute(self.people["requester"], item, step=self.counter)

    @rule(
        command=st.one_of(st.just("ｅxecute_export"), st.just("EXECUTE_EXPORT"), st.text(max_size=8)),
        stale_by=st.integers(min_value=1, max_value=4),
    )
    def attack(self, command: str, stale_by: int) -> None:
        before = self.workflow.snapshot()
        item = lab.request(
            command,
            self.next_operation("attack"),
            state_version=max(0, self.workflow.version - stale_by),
        )
        receipt = self.gateway.execute(self.people["requester"], item, step=self.counter)
        assert not receipt.effect_applied
        assert self.workflow.snapshot() == before

    @invariant()
    def effects_require_exact_approved_execution(self) -> None:
        assert len(self.workflow.effects) <= 1
        if self.workflow.effects:
            assert self.workflow.state is lab.WorkflowState.EXECUTED

    @invariant()
    def version_matches_successful_transitions(self) -> None:
        assert self.workflow.version >= 0
        assert self.workflow.version <= 3


def run_hypothesis_suite() -> dict[str, object]:
    property_untrusted_identity_never_authorizes_cross_tenant_effect()
    property_malformed_input_never_changes_secure_state()
    run_state_machine_as_test(
        SecureWorkflowMachine,
        settings=settings(
            max_examples=40,
            stateful_step_count=12,
            derandomize=True,
            database=None,
            deadline=None,
        ),
    )
    return {
        "properties": 2,
        "examples_per_property": 80,
        "stateful_scenarios": 40,
        "stateful_steps": 12,
        "counterexample": find_unsafe_encoded_bypass(),
    }


if __name__ == "__main__":
    import json

    print(json.dumps(run_hypothesis_suite(), indent=2, default=str))
