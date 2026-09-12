# 15 — Agentic RAG Security

Model documents → ingestion → index → retrieval → context → agent. Attack a
poisoned document, unauthorized retrieval, stale source, malicious metadata,
cross-tenant vector result, and injected passage. Require ingestion provenance,
authorization-aware retrieval, freshness, citations, and context policy. Extend
`labs/beginner/03_secure_research_agent.py`; evaluate leakage, injection-follow
rate, source authorization, and citation correctness.
