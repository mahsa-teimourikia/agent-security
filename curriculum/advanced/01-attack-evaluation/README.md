# Advanced 01 — Agent Security Attack Evaluation

## Capability

Turn a versioned mix of adversarial and valid-task cases into interpretable
security metrics and a fail-closed production decision.

## Learning outcomes

You will be able to define typed attack cases, preserve correct denominators,
measure attack success and utility cost separately, demand complete trace and
case coverage, and prevent severe failures from disappearing inside averages.

Prerequisite: [Intermediate 03 — Incident Response and Recovery](../../intermediate/03-incident-recovery/README.md).

Next: [Advanced 02 — Multi-Agent Delegation Security](../02-multi-agent-security/README.md).

## Governing invariant

> One high- or critical-severity unauthorized success blocks release even when
> aggregate scores improve.

## Evaluation contract

An `AttackCase` declares a stable identifier, family, severity, whether the
case is adversarial, and the expected control. A `CaseResult` records whether
the operation was blocked, whether the trajectory is traceable, and which
control was observed. Trusted evaluation code—not a model self-assessment—joins
the two lists and computes the decision.

```text
versioned cases ─┐
                 ├─> trusted evaluator ─> metrics + explicit blockers
observed results ┘           │
                             └─ missing, untraceable, mismatched, severe
```

The separation matters. Adversarial cases answer “did the attack succeed?”
while valid cases answer “did security block useful work?” Combining the two
under one accuracy score hides both risks.

## Practical lab

```bash
python3 curriculum/advanced/01-attack-evaluation/01_attack_evaluation.py
jupyter notebook curriculum/advanced/01-attack-evaluation/01_attack_evaluation.ipynb
```

The lab evaluates a safe run, injects a critical scope failure, and shows why
the second result cannot pass. Try these additional failures:

- omit a case result to reduce case coverage;
- remove traceability from an otherwise blocked attack;
- report a control different from the case contract;
- block a valid case and lower the false-block threshold; or
- duplicate a case identifier and observe input validation fail.

## Metrics and denominators

| Metric | Numerator | Denominator | Release meaning |
| --- | --- | --- | --- |
| attack success rate | adversarial cases not blocked | all adversarial cases | lower is safer |
| severe attack successes | high/critical attacks not blocked | count | must be zero |
| false-block rate | valid cases blocked | all valid cases | bounded utility cost |
| trace coverage | traceable known results | all declared cases | must be complete |
| case coverage | known results | all declared cases | must be complete |

Real programs should also segment results by model, prompt, policy, tool,
tenant, language, environment, and attack family. Report confidence intervals
where sampling is involved, retain raw non-sensitive receipts, and compare
against a pinned baseline. Averages without environment and suite versions are
not reproducible release evidence.

## Production considerations

Protect the evaluation corpus from training leakage and unauthorized edits.
Use independent review for severity and expected outcomes. Test false allows,
false blocks, unavailable dependencies, and degraded modes. Treat an evaluator
or judge model as a fallible measurement component; calibrate it against human
labels and deterministic properties. Keep severe blockers outside any weighted
average.

Residual risks include incomplete attack coverage, adaptive attacks, judge
bias, benchmark contamination, and differences between the test harness and
production. Continuous runtime assurance complements—not replaces—pre-release
evaluation.

## Checkpoint

A release has a 1% attack success rate, but its only success is an unauthorized
payment in a critical case. The previous release had 3% ASR. Ship it?

- A. Yes, because the average improved.
- B. No, because the explicit severe-failure invariant was violated.
- C. Yes, if a judge model rates the answer as fluent.

**Answer: B.** Risk acceptance may be a governed human decision, but a severe
failure cannot be erased by an aggregate metric.

## References

- [NIST AI 600-1 Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
- [MITRE ATLAS](https://atlas.mitre.org/)
