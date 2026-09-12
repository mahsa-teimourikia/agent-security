# 28 — Secure Long-Running Agents

Secure agents that pause, schedule, and resume across credential/policy/model
changes. Require signed checkpoint integrity, version checks, reauthorization,
idempotency, approval freshness, and safe resume. Attack stale state, replayed
events, expired credentials, and contaminated memory; unsafe resume and duplicate
side effects must be zero.
