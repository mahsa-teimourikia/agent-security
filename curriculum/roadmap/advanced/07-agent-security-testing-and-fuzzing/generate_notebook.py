"""Generate the Advanced 07 notebook deterministically."""
from __future__ import annotations

from pathlib import Path

import nbformat as nbf


ROOT = Path(__file__).parent
OUTPUT = ROOT / "agent_security_testing_and_fuzzing.ipynb"


def markdown(cell_id: str, source: str):
    cell = nbf.v4.new_markdown_cell(source.strip())
    cell["id"] = cell_id
    return cell


def code(cell_id: str, source: str):
    cell = nbf.v4.new_code_cell(source.strip())
    cell["id"] = cell_id
    return cell


def build_notebook():
    notebook = nbf.v4.new_notebook()
    notebook["metadata"] = {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python", "version": "3.11"},
    }
    notebook["cells"] = [
        markdown(
            "a07-title",
            """
# Advanced 07 — Agent Security Testing and Fuzzing

**Goal:** generate meaningful values and command sequences around explicit
security invariants, observe real target state and effects, shrink verified
failures without changing their semantics, and retain reproducible regressions.

The default path uses deterministic synthetic data, a real Hypothesis adapter,
and no model, network, credential, or external side effect.

![Security fuzzing lifecycle](architecture.svg)
""",
        ),
        markdown(
            "a07-contract",
            """
## Security contract

Generators and models may propose. The application parses, authenticates,
authorizes, persists, executes, and verifies. A target's `DENY` label is not
proof: the oracle independently observes durable state and effects.
""",
        ),
        code(
            "a07-imports",
            """
from dataclasses import asdict, replace
import json

import hypothesis
import lab
import hypothesis_adapter as hyp

print({"hypothesis": hypothesis.__version__, "policy": lab.POLICY_VERSION})
""",
        ),
        markdown(
            "a07-scenario",
            """
## 1. Inspect the typed workflow

Northstar's support agent can read a case or move an export workflow through
`DRAFT -> REVIEW -> APPROVED -> EXECUTED`. Every mutation carries an expected
version. Export requires an exact one-use approval and an allowed destination.
""",
        ),
        code(
            "a07-workflow-contract",
            """
print({
    "commands": [item.value for item in lab.Command],
    "states": [item.value for item in lab.WorkflowState],
    "transitions": {
        f"{state.value} + {command.value}": target.value
        for (state, command), target in lab.ALLOWED_TRANSITIONS.items()
    },
})
""",
        ),
        markdown(
            "a07-corpus-heading",
            """
## 2. Keep evaluation populations explicit

Valid, attack, boundary, and dependency-failure cases have different meanings
and denominators. Generated cases extend this release corpus; they do not erase
its labels.
""",
        ),
        code(
            "a07-corpus",
            """
corpus = lab.build_corpus()
population = {
    kind.value: sum(case.kind is kind for case in corpus)
    for kind in lab.CaseKind
}
print(population)
assert population == {"valid": 5, "attack": 14, "boundary": 4, "failure": 3}
""",
        ),
        markdown(
            "a07-baseline-heading",
            """
## 3. Quantify the unsafe baseline

The baseline trusts claimed tenant text, uses different command parsing in its
guard and executor, ignores exact replay binding, and reports a missing policy
dependency as success. Its stable execution is not security.
""",
        ),
        code(
            "a07-baseline",
            """
unsafe_report, unsafe_results = lab.evaluate(lab.UnsafeGateway)
print(asdict(unsafe_report))
unsafe_findings = [
    (item.case_id, item.receipt.reason, [finding.family for finding in item.findings])
    for item in unsafe_results if item.forbidden_outcome
]
print(json.dumps(unsafe_findings, indent=2))
assert unsafe_report.forbidden_outcomes == 5
assert unsafe_report.fail_open_dependency_outcomes == 3
assert unsafe_report.unique_failure_families == 7
""",
        ),
        markdown(
            "a07-oracle",
            """
## Oracle interpretation

`SecurityOracle` checks postconditions: cross-tenant effects, role-free effects,
encoded execution, missing approval, illegal pre-state, stale mutation,
duplicate effects, and fake-success fallback. A blocked attempt is not counted
as a violation.
""",
        ),
        code(
            "a07-blocked-vs-violation",
            """
encoded_case = next(case for case in corpus if case.case_id == "attack-fullwidth-command")
unsafe_encoded = lab.run_case(encoded_case, lab.UnsafeGateway)
secure_encoded = lab.run_case(encoded_case, lab.SecureGateway)
print({
    "unsafe": asdict(unsafe_encoded.receipt),
    "unsafe_families": [item.family for item in unsafe_encoded.findings],
    "secure": asdict(secure_encoded.receipt),
    "secure_families": [item.family for item in secure_encoded.findings],
})
assert unsafe_encoded.receipt.effect_applied and unsafe_encoded.forbidden_outcome
assert secure_encoded.receipt.status is lab.DecisionStatus.DENY
assert not secure_encoded.forbidden_outcome
""",
        ),
        markdown(
            "a07-secure-heading",
            """
## 4. Evaluate the secure gateway

The secure path requires canonical known commands, authenticated actor context,
current resource ownership and role, exact workflow version, legal transition,
idempotent operation identity, and exact approval before the effect.
""",
        ),
        code(
            "a07-secure",
            """
secure_report, secure_results = lab.evaluate(lab.SecureGateway)
print(asdict(secure_report))
assert secure_report.forbidden_outcomes == 0
assert secure_report.contained_attack_rate == 1.0
assert secure_report.valid_case_rejection_rate == 0.0
assert secure_report.explicit_dependency_errors == 3
""",
        ),
        markdown(
            "a07-metric-heading",
            """
## 5. Compare metrics without averaging populations

Violation and containment use fourteen attacks. Valid rejection uses five valid
cases. Dependency errors use three failure cases. Zero valid rejection does not
rescue a design with forbidden effects.
""",
        ),
        code(
            "a07-metrics",
            """
comparison = {
    report.implementation: {
        "attacks": report.attack_cases,
        "forbidden_outcomes": report.forbidden_outcomes,
        "violation_rate": report.invariant_violation_rate,
        "contained_attack_rate": report.contained_attack_rate,
        "valid_rejection_rate": report.valid_case_rejection_rate,
        "dependency_errors": report.explicit_dependency_errors,
        "fail_open_dependencies": report.fail_open_dependency_outcomes,
        "reproducibility_rate": report.reproducibility_rate,
    }
    for report in (unsafe_report, secure_report)
}
print(json.dumps(comparison, indent=2))
assert comparison["secure-gateway"]["reproducibility_rate"] == 1.0
""",
        ),
        markdown(
            "a07-hypothesis-find-heading",
            """
## 6. Let Hypothesis find a parser differential

The predicate checks whether the unsafe target created an effect. It does not
merely classify an input as suspicious. Hypothesis returns a compact
counterexample, which we replay against the secure boundary.
""",
        ),
        code(
            "a07-hypothesis-find",
            """
counterexample = hyp.find_unsafe_encoded_bypass()
print(counterexample)
assert counterexample["unsafe_effect"] is True
assert counterexample["secure_status"] == "deny"
assert counterexample["secure_reason"] == "command-not-canonical"
""",
        ),
        markdown(
            "a07-properties-heading",
            """
## 7. Run generated properties and a rule-based state machine

Two `@given` properties explore claimed identity, unknown commands, operation
sizes, and payload sizes. The state machine generates valid and adversarial
actions, applying invariants after every step.
""",
        ),
        code(
            "a07-properties",
            """
hypothesis_result = hyp.run_hypothesis_suite()
print(json.dumps(hypothesis_result, indent=2))
assert hypothesis_result["properties"] == 2
assert hypothesis_result["stateful_scenarios"] == 40
""",
        ),
        markdown(
            "a07-race-heading",
            """
## 8. Generate around the concurrency boundary

Two commands race from the same expected version. This is a deterministic
model of compare-and-swap semantics, not a claim about a particular database or
scheduler.
""",
        ),
        code(
            "a07-race",
            """
first, second = lab.race_scenario()
print(asdict(first))
print(asdict(second))
assert first.status is lab.DecisionStatus.ALLOW
assert second.reason == "workflow-version-stale"
""",
        ),
        markdown(
            "a07-approval-heading",
            """
## 9. Mutate an exact approval

Approval identity and freshness are insufficient when the proposed destination
changes. The proposal digest binds every effect-relevant field.
""",
        ),
        code(
            "a07-approval",
            """
valid_execute = next(case for case in corpus if case.case_id == "valid-execute")
gateway, workflow, approvals = lab.build_gateway(lab.SecureGateway, valid_execute)
altered = replace(valid_execute.request, destination="alternate.northstar.example")
altered_receipt = gateway.execute(valid_execute.actor, altered, step=1)
print(asdict(altered_receipt))
assert altered_receipt.reason == "approval-proposal-binding"
assert not workflow.effects
""",
        ),
        markdown(
            "a07-failure-heading",
            """
## 10. Inject policy dependency failure

An unavailable policy boundary is neither an attack denial nor evidence of safe
execution. The secure result is explicit `ERROR` with no state change or effect.
""",
        ),
        code(
            "a07-failure",
            """
failure_cases = [case for case in corpus if case.kind is lab.CaseKind.FAILURE]
failure_results = [lab.run_case(case, lab.SecureGateway) for case in failure_cases]
print([(item.case_id, item.receipt.status.value, item.receipt.reason) for item in failure_results])
assert all(item.receipt.status is lab.DecisionStatus.ERROR for item in failure_results)
assert all(not item.receipt.effect_applied for item in failure_results)
""",
        ),
        markdown(
            "a07-shrink-heading",
            """
## 11. Shrink a sequence while preserving semantics

The teaching minimizer deletes actions only when the same oracle-confirmed
unsafe outcome remains. Hypothesis performs richer integrated shrinking; this
step exposes the retention contract.
""",
        ),
        code(
            "a07-shrink",
            """
original = lab.encoded_bypass_sequence()
minimal = lab.minimize_sequence(original, lab.sequence_has_unsafe_forbidden_outcome)
print({
    "before": [item.command for item in original],
    "after": [item.command for item in minimal],
    "reproduces": lab.sequence_has_unsafe_forbidden_outcome(minimal),
})
assert len(original) == 4 and len(minimal) == 3
assert not lab.sequence_has_unsafe_forbidden_outcome(minimal[:-1])
""",
        ),
        markdown(
            "a07-landscape",
            """
## 12. Choose the engine by target shape

| Target | First choice | Why |
| --- | --- | --- |
| typed Python policy and workflow | Hypothesis | strategies, state machines, readable shrinking |
| OpenAPI/GraphQL service | Schemathesis | schema-derived cases and linked stateful operations |
| Python parser/native extension | Atheris + libFuzzer | coverage guidance and sanitizer integration |
| network protocol/session | boofuzz | grammar, session graphs, target monitors and reset |
| bounded repository fuzzing | ClusterFuzzLite | PR/batch integration |
| sustained open-source campaign | OSS-Fuzz | managed continuous distributed fuzzing |

No engine replaces an application security oracle or safe target isolation.
""",
        ),
        markdown(
            "a07-production",
            """
## 13. Production upgrade path

- replace in-memory state with a transactional store and real compare-and-swap;
- run untrusted targets in disposable capability-bounded environments;
- use synthetic tenants, narrow test identity, no production credentials, and
  verified cleanup;
- keep fast retained regressions and PR budgets, plus longer scheduled runs;
- content-address the corpus and bind each finding to build, policy, environment,
  generator, invariant, severity, and owner;
- report harness errors and missing execution as incomplete, never defended; and
- admit signed complete evidence to a release gate without averaging away a
  severe forbidden outcome.
""",
        ),
        markdown(
            "a07-exercises",
            """
## Exercises

1. Add a legal `REOPEN` transition from `CANCELLED` and generated attacks from
   every other state.
2. Build a structured `ActionRequest` strategy that targets exact size limits
   without rejecting most generated examples.
3. Make the minimizer preserve a specific family instead of any finding, then
   construct a two-failure sequence that demonstrates why it matters.
4. Design an isolated Schemathesis extension for an ASGI wrapper without letting
   generated request fields establish authenticated identity.
5. Define a release policy over severe outcomes, valid rejection, execution
   completeness, and harness errors.
""",
        ),
        markdown(
            "a07-summary",
            """
## Summary

Generate broadly, but judge narrowly with explicit application-owned
invariants. Observe real state and effects, separate populations and errors,
preserve semantics while shrinking, and retain every verified failure as a
versioned owned regression. Coverage guides exploration; it never authorizes an
agent action or proves absence of a security defect.
""",
        ),
    ]
    return notebook


def main() -> None:
    notebook = build_notebook()
    nbf.write(notebook, OUTPUT)
    print(f"wrote {OUTPUT.name} with {len(notebook['cells'])} cells")


if __name__ == "__main__":
    main()
