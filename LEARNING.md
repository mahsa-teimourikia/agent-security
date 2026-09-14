# How to study the curriculum

Use each published lesson as a security experiment, not a passive reading.

## The learning loop

1. **Name the boundary.** Identify which values are untrusted and which
   component is allowed to authenticate, authorize, persist, or execute.
2. **State the invariant.** Write one property that must remain true even when
   the model follows malicious content.
3. **Run the safe baseline.** Execute the notebook top to bottom and inspect the
   decision receipt, state transition, or evaluation report.
4. **Inject one failure.** Change only one relevant assumption—tenant, scope,
   audience, schema, expiry, provenance, checkpoint, or approval.
5. **Attempt a bypass.** Try an indirect resource, encoded instruction, replay,
   stale state, or dependency failure rather than stopping at the obvious case.
6. **Write a regression test.** Make the invariant executable without relying
   on private model reasoning or an external credential.
7. **Map to production.** Replace every in-memory teaching boundary with the
   real identity, policy, isolation, storage, telemetry, and response control.

## Evidence journal

For each course, record:

- the protected asset and attacker influence;
- the trusted enforcement point;
- the allowed, denied, paused, or contained terminal state;
- the exact reason and safe identifiers in the receipt;
- the metric and denominator;
- a residual risk and accountable owner; and
- the next test you would add before production.

Do not treat a fluent answer, a model’s confidence, a prompt instruction, or a
green happy-path demo as security evidence.

## Recommended sequence

Complete the nine [published lessons](COURSE_MAP.md) first. Use the
[thirty-six-course roadmap](curriculum/README.md) as additional reading, but
respect its Reading, Pilot, and Planned labels. The Learning Hub shows exactly
which evidence still separates each roadmap topic from publication.
