# 10 — Agent Identity and Delegated Authority

Trace user → orchestrator → specialist → tool with user, workload, agent, and
down-scoped delegated identity. The invariant is `child authority ⊆ parent
authority`; test tenant swap, scope escalation, laundering, and confused deputy.
Extend `labs/intermediate/01_identity_propagation.py` with audience, expiry,
purpose, and delegation chain. Evaluate escalation success and attribution.
