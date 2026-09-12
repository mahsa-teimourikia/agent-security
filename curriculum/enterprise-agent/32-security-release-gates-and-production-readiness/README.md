# 32 — Security Release Gates and Production Readiness

Block release on any severe unauthorized action, injection success, secret
exposure, cross-tenant leakage, approval bypass, unsafe retry, memory-poisoning
success, or failed control—even if averages improve. Require threat model,
adversarial suite, rollback drill, named owner, trace coverage, adversarial p95
latency/cost, and canary plan. Extend `labs/advanced/03_production_gate.py`.
