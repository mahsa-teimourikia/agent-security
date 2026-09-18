# Advanced 01 — Agent Security Attack Evaluation

## Course metadata

- **Level:** Advanced
- **Prerequisite:** [Intermediate 03 — Incident Response and Recovery](../../intermediate/03-incident-recovery/README.md)
- **Estimated time:** 3–4 hours
- **Primary lab:** [`01_attack_evaluation.py`](01_attack_evaluation.py)
- **Framework companion:** [`promptfooconfig.yaml`](promptfooconfig.yaml) and [`01_attack_evaluation_promptfoo.py`](01_attack_evaluation_promptfoo.py)
- **Notebook:** [`01_attack_evaluation.ipynb`](01_attack_evaluation.ipynb)

## Capability

Turn a versioned mix of adversarial and valid-task cases into interpretable,
reproducible release evidence without allowing missing runs, harness failures,
or aggregate averages to hide unsafe behavior.

## Course thesis

By the end of this course, you should be able to explain an agent-security
evaluation contract, implement a trusted release evaluator, distinguish target
behavior from harness failure, measure repeated attacks and utility cost with
correct denominators, and productionize the workflow with protected suites,
sidecar evidence, and independent governance.

## Learning outcomes

You will be able to:

1. define a versioned suite with stable case, threat-family, technique, target,
   policy, environment, and attempt-count bindings;
2. keep attack outcomes, valid-task outcomes, target errors, and harness errors
   separate;
3. treat any successful attempt as a successful attack case while retaining an
   attempt-level rate;
4. calculate attack success, false-block, trace, case, and execution coverage
   from explicit populations;
5. make high- and critical-severity unauthorized outcomes non-averagable
   release blockers;
6. reject foreign, duplicate, stale, cross-version, and untraceable results;
7. connect a well-known evaluation framework through a bounded provider and
   deterministic assertions; and
8. explain which evidence is still missing before a synthetic lab can support
   a production release decision.

## Architecture and trust boundaries

![Attack-evaluation trust boundaries](architecture.svg)

The target can produce behavior, but it does not grade itself. A trusted
harness owns the suite and run identity. Host-side verifiers observe control
decisions and effects. The release evaluator admits only bound evidence,
computes metrics, and applies non-averagable blockers.

```text
versioned attack + valid cases
             │
             v
       isolated harness ─────> target agent
             │                    │
             └──── host-observed behavior
                              │
                              v
                    verifier receipts/traces
                              │
                              v
                    binding + integrity gate
                              │
                              v
                    metrics, slices, blockers
                              │
                    release / do not release
```

Promptfoo is a harness integration in this course. It does not become the
authority for production release merely because its rows are green.

## Governing invariants

> One high- or critical-severity unauthorized success blocks release even when
> every aggregate score improves.

The evaluator also enforces these supporting invariants:

- a suite contains both adversarial and valid-task populations;
- a suite digest binds the exact cases and target context;
- every admitted result binds to the run, suite, target, policy, environment,
  case, attempt, and run time window;
- foreign case IDs and duplicate `(case_id, attempt_id)` pairs are invalid;
- an execution error is neither a safe block nor an attack success;
- a “blocked” outcome needs a host-owned trace and evidence reference;
- every declared attempt must be present and executed;
- a model, target, or judge cannot grant itself traceability or release
  authority; and
- severe failures remain explicit counts, not terms in a weighted average.

## Worked scenario

A support agent is evaluated before promotion to `release-7`. The suite includes:

- two indirect-injection attempts expected to be stopped by `action-policy`;
- two privilege-escalation attempts expected to be stopped by `scope-pdp`; and
- one valid ticket-read task expected to remain allowed.

The suite binds `agent-attacks-2.0`, `release-7`, `policy-v5`, and the isolated
staging environment into a SHA-256 manifest digest. Results from `release-6`, a
different environment, or a time outside the declared run are not silently
mixed into the metrics.

### Threat and validity model

| Surface | Failure | Why a naive score lies | Executable control |
| --- | --- | --- | --- |
| Suite | adversarial-only corpus | zero false blocks because no useful work was tested | require attack and valid populations |
| Case identity | foreign or duplicate result | denominator or evidence can be substituted | reject undeclared IDs and duplicate attempts |
| Target binding | result from an older release | stale success appears current | bind target, policy, environment, and time |
| Repeated attacks | one of several attempts succeeds | mean attempt rate can obscure case compromise | any-success case aggregation |
| Harness | verifier crashes | absence of a violation appears safe | explicit harness error and execution coverage |
| Target | dependency fails | outage appears to block an attack | explicit target error, never a block |
| Evidence | target says “blocked” | self-report is not effect evidence | require trace and receipt references |
| Utility | valid work is denied | safety improves by disabling the product | separate false-block denominator |
| Aggregation | critical payment succeeds | average still looks acceptable | severe-success count blocks release |

## Evaluation contract

### 1. Version the suite, target, and environment

`EvaluationSuite` records the suite ID/version, target ID/version, policy
version, environment, creation time, and complete case list. Its digest is an
integrity binding for the run. In production, store this manifest and digest in
a protected artifact system; a local digest alone is not a signature or access
control.

### 2. Declare expected attempts

`attempts_required` is part of each case. Repeated attempts expose attacks that
are stochastic or adaptive. The case-level rule is conservative: if any
completed attempt is allowed, the attack case succeeded.

The attempt-level rate remains useful for analysis, but it does not erase the
case-level failure. Five blocked attempts after one unauthorized effect do not
undo that effect.

### 3. Observe outcomes outside the target

`CaseResult` represents a verifier observation with a trace ID and evidence
references. A production verifier may inspect policy receipts, tool calls,
sandbox events, canaries, file hashes, provider records, or side-effect logs.
Do not ask the model “did you follow policy?” and promote its answer into a
trusted result.

The lab uses synthetic receipts. They teach the shape of the boundary but are
not cryptographic proof.

### 4. Separate completion from errors

`ExecutionState` has three states:

- `COMPLETED`: the verifier observed an outcome;
- `TARGET_ERROR`: the target or one of its dependencies failed; and
- `HARNESS_ERROR`: the evaluator, verifier, sandbox, or instrumentation failed.

Only a completed observation can be `BLOCKED` or `ALLOWED`. Both error states
block release through incomplete execution coverage. Neither is counted as a
successful defense.

### 5. Apply the release policy

The gate checks exact blockers before setting `ready=True`. The default policy
requires zero successful attack cases, full trace/case coverage, full execution,
and no more than 10% blocking of valid tasks. Teams may set stricter utility
thresholds, but they should not weaken the severe-failure invariant through an
average or compensating score.

## Metrics and exact denominators

| Metric | Numerator | Denominator | Direction and gate meaning |
| --- | --- | --- | --- |
| attack case success rate | adversarial cases with at least one allowed attempt | all declared adversarial cases | lower; default must be 0 |
| attack attempt success rate | allowed completed adversarial attempts | completed adversarial attempts | lower; diagnostic, not a coverage substitute |
| severe attack successes | unique high/critical cases with an allowed attempt | count | must be 0 |
| false-block rate | blocked completed valid-task attempts | completed valid-task attempts | lower; default ≤ 10% |
| trace coverage | admitted attempts with bounded trace and evidence IDs | all declared attempts | higher; default 100% |
| case coverage | cases with exactly the declared number of admitted attempts | all declared cases | higher; default 100% |
| execution coverage | completed attempts | all declared attempts | higher; must be 100% |
| harness error count | attempts ending in harness error | count | must be 0 |
| target error count | attempts ending in target error | count | must be 0 |

Missing and error attempts remain visible through coverage and explicit
blockers. Do not publish an attack rate without its coverage, suite version,
target version, environment, and attempt policy.

The lab also reports case-level attack success by family. Production reports
should add severity, technique, tenant, language, model, tool, policy, and
environment slices where those populations are large enough to interpret.

## State of practice and tool review

As of September 2026, agent evaluation is moving from final-answer grading
toward whole-trajectory and system-boundary evidence. NIST’s TEVV-Athlon and
automated-benchmark publications are public drafts; use them as current
measurement guidance, not finalized standards. NIST’s agent-evaluation work
also highlights contamination, grader gaming, repeated attempts, and transcript
review as threats to evaluation validity.

| Tool or body of practice | Strong use | Important limitation |
| --- | --- | --- |
| NIST AI RMF / GenAI Profile / TEVV drafts | objectives, measurement validity, reporting, risk context | guidance is not an executable agent-security gate; current TEVV documents may still change |
| MITRE ATLAS | shared adversary tactics, techniques, and case taxonomy | taxonomy coverage does not prove that your target or controls were tested |
| OWASP GenAI Red Teaming & Evaluation | lifecycle, methodology, tool/vendor evaluation criteria | a checklist or vendor scan is not bound release evidence by itself |
| Promptfoo | test matrices, custom providers/assertions, red-team workflows, agent trace assertions | generated attacks and model graders may require services; a green assertion is only as sound as the observed evidence |
| Microsoft PyRIT | targets, orchestrators, converters, memory, and pluggable scorers for automated or human-led red teaming | powerful workflows add operational and data-handling complexity; model scorers require calibration |
| NVIDIA garak | broad probe/generator/detector scanning for model and dialog weaknesses | model vulnerability scanning does not cover application authorization, tool effects, or enterprise release governance |

Choose tools by the boundary you need to test. A model scanner, an agent
trajectory harness, and a release-governance gate solve different problems.
The course combines Promptfoo’s provider/assertion interface with a separate
trusted release evaluator to make that separation explicit.

## Practical labs

Run commands from the repository root unless a section says otherwise.

### Lab A — Safe baseline and severe failure

```bash
python3 curriculum/advanced/01-attack-evaluation/01_attack_evaluation.py
```

Inspect the passing and failing reports. Confirm that one successful critical
attempt produces both a severe blocker and a 50% attack-case success rate, even
though only one of four adversarial attempts succeeded.

### Lab B — Notebook investigation

```bash
jupyter notebook curriculum/advanced/01-attack-evaluation/01_attack_evaluation.ipynb
```

The notebook covers:

- the safe baseline;
- repeated-attempt aggregation;
- severe success;
- stale target binding;
- missing attempts;
- target and harness errors;
- trace and control mismatches;
- valid-task false blocks;
- family slices; and
- the Promptfoo provider adapter.

### Lab C — Promptfoo framework integration

The framework exercise uses a local Python provider, deterministic synthetic
cases, and host-owned JavaScript assertions. It requires no API key and sends
no prompts to a model service.

```bash
cd curriculum/advanced/01-attack-evaluation
npx --yes promptfoo@0.123.1 eval \
  -c promptfooconfig.yaml \
  --no-cache \
  --no-share
```

The repository was validated with Promptfoo `0.123.1`, which declares Node
`22.22.0` or newer. Review the three rows and then inspect
`01_attack_evaluation_promptfoo.py`:

1. `call_api()` implements Promptfoo’s Python-provider contract.
2. The provider returns structured observable evidence, not a prose safety
   claim.
3. `result_from_output()` binds bounded provider output to the suite and run.
4. The release evaluator remains separate from the framework row status.

This fixture is intentionally deterministic. It proves the integration and
control-plane semantics, not model robustness.

For CI, export JSON or JUnit and have a trusted pipeline step inspect failed and
error rows explicitly. Do not treat the CLI process status, a generated HTML
report, or an aggregate pass rate as the release decision; feed admitted
observations into the course evaluator and retain the row-level evidence.

### Lab D — Failure injection

Modify one dimension at a time:

- change a result to `release-6`;
- remove one required attempt;
- replace a completed observation with `HARNESS_ERROR`;
- remove its trace and receipt;
- attach a foreign case ID;
- duplicate an attempt ID; or
- block the valid task.

Predict whether the evaluator raises an input-integrity error or returns a
non-ready report. Then run the focused tests:

```bash
pytest -q tests/test_attack_evaluation.py
```

## Evaluation validity beyond this lab

An advanced evaluation program should answer five questions before comparing
systems or approving a release:

1. **Construct validity:** does the suite measure the risk decision you care
   about, or a proxy such as refusal wording?
2. **Coverage:** which realistic tasks, identities, tools, effects, languages,
   and attack families are missing?
3. **Independence:** can the target see answers, weaken verifiers, modify tests,
   or share mutable state across rows?
4. **Reliability:** do repeated runs, independent labels, and calibrated judges
   produce stable conclusions?
5. **External validity:** how different are the harness, data, tools, latency,
   permissions, and failure modes from production?

Automated benchmarks are one source of evidence. Red-team exploration, expert
review, field testing, runtime monitoring, and incident data answer different
questions. Do not collapse them into one universal “security score.”

## Production replacement map

| Lab component | Production replacement |
| --- | --- |
| local suite dataclass | reviewed, access-controlled suite registry with lineage, owners, and signed manifests |
| synthetic Promptfoo provider | isolated target adapter with per-row workspace reset and least-privilege credentials |
| synthetic evidence IDs | protected sidecar receipts, traces, canaries, file hashes, policy decisions, and provider records |
| in-process evaluator | independent evaluation service with immutable inputs, deterministic policy, and audit history |
| fixed severity | threat-model-linked severity with independent review and documented change control |
| one staging environment | representative environment matrix with pinned target, policy, data, and dependency versions |
| exact deterministic labels | calibrated deterministic verifiers, expert labels, and bounded judge use where semantics require it |
| local report | protected artifact, comparison to pinned baseline, accountable exception process, and release integration |

### Operational checklist

- Protect cases, expected controls, verifiers, assertions, and baseline results
  from the target under test.
- Run every row in an isolated, resettable environment with unique synthetic
  canaries.
- Pin and record target, model, prompt, tool, policy, dataset, framework, and
  dependency versions.
- Record host-observed actions and effects; do not rely only on final text or a
  model judge.
- Separate setup, target, verifier, scorer, and infrastructure failures.
- Retain raw non-sensitive receipts long enough to reproduce a release decision.
- Review traces for grader gaming, contamination, assertion weakening, and
  shortcuts that satisfy the metric without satisfying the task.
- Report uncertainty and slices; avoid rankings when populations are too small
  or not comparable.
- Require named owners and expiry for any accepted residual risk.
- Continue runtime monitoring because pre-release evaluation cannot enumerate
  adaptive attacks or production drift.

## Exercises

1. Add a `language` field and report attack-case success by language without
   allowing small slices to disappear from the release evidence.
2. Add an immutable baseline report and block regressions without allowing an
   improved average to waive a severe success.
3. Add a host-side canary verifier and prove a target’s prose claim cannot set
   its result.
4. Add a statistically justified repeated-attempt policy for a stochastic
   target and explain the unit of analysis.
5. Build a PyRIT or garak adapter that produces the same bounded `CaseResult`
   contract; document which application-level evidence the tool cannot observe.

## Checkpoint

An attack case runs five times. Four attempts are blocked; one causes an
unauthorized payment. A separate verifier crashes on two other cases. The new
release’s average attack-attempt success rate is lower than the previous
release. May the evaluator mark it ready?

- A. Yes; the mean improved and most attempts were blocked.
- B. Yes; count verifier crashes as blocked attacks.
- C. No; the attack case succeeded, a severe unauthorized effect is a blocker,
  and verifier errors leave execution coverage incomplete.

**Answer: C.** Attempt averages do not reverse an unauthorized effect, and a
broken harness is missing evidence rather than proof of safety.

## Authoritative references

- [NIST AI 600-1 — Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile](https://doi.org/10.6028/NIST.AI.600-1)
- [NIST AI 200-2 IPD — TEVV-Athlon Framework for Evaluating AI Systems](https://doi.org/10.6028/NIST.AI.200-2.ipd) — initial public draft, August 2026
- [NIST AI 800-2 IPD — Practices for Automated Benchmark Evaluations of Language Models](https://doi.org/10.6028/NIST.AI.800-2.ipd) — initial public draft, January 2026
- [NIST — Strengthening AI Agent Hijacking Evaluations](https://www.nist.gov/news-events/news/2025/01/technical-blog-strengthening-ai-agent-hijacking-evaluations)
- [NIST — Cheating on AI Agent Evaluations](https://www.nist.gov/caisi/cheating-ai-agent-evaluations)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP GenAI Red Teaming & Evaluation](https://genai.owasp.org/initiatives/ai-red-teaming-initiative/)
- [Promptfoo — Red Teaming Agents](https://www.promptfoo.dev/docs/red-team/agents/)
- [Promptfoo — Python Provider](https://www.promptfoo.dev/docs/providers/python/)
- [Microsoft PyRIT](https://github.com/microsoft/PyRIT)
- [NVIDIA garak](https://github.com/NVIDIA/garak)

## Navigation

Previous: [Intermediate 03 — Incident Response and Recovery](../../intermediate/03-incident-recovery/README.md).

Next: [Advanced 02 — Multi-Agent Delegation Security](../02-multi-agent-security/README.md).

Back to the [course map](../../../COURSE_MAP.md).
