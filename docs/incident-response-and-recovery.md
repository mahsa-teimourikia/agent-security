# Intermediate: incident response and recovery

Treat unsafe tool calls, data leaks, prompt-injection success, and runaway loops as incidents with an owner and evidence trail.

```mermaid
flowchart TD
 D[Detect] --> T[Triage identity, tenant, tools]
 T --> C[Contain: pause run or revoke token]
 C --> E[Eradicate poisoned state and fix policy]
 E --> R[Recover with checkpoints and idempotency]
 R --> L[Learn: regression test and review]
```

Run `python labs/intermediate/03_incident_recovery.py`. Short-lived credentials, kill switches, idempotency keys, and human approval protect irreversible actions. Never blindly retry an unknown payment, deletion, or permission change. References: [Google SAIF](https://cloud.google.com/use-cases/secure-ai-framework), [OWASP Agentic Security](https://genai.owasp.org/initiatives/agentic-security-initiative/), and [OpenAI human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/).
