# 26 — Agent Security Observability and Runtime Assurance

Instrument user → agent → model → retriever → tool → memory → sub-agent →
action using privacy-aware OpenTelemetry-style traces. Capture principal, tenant,
tool, argument hash, policy, approval, source IDs, network destination, latency,
cost, checkpoint, and terminal reason. Test attribution coverage and redaction;
avoid storing raw secrets or hidden reasoning.
