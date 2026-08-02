# Agent Security Learning Hub

A comprehensive, source-linked curriculum for securing AI agents, agentic workflows, tools, memory, protocols, and multi-agent systems.

## Start with the Learning Hub

**[Open the Agent Security Learning Hub →](https://mahsa-teimourikia.github.io/agent-security/)**

The Hub is organized into Beginner, Intermediate, and Advanced paths. Each lesson follows **Learn → Lab → Checkpoint**, includes theory and references, links to runnable Python code and notebooks, and records completion locally in the browser.

Take the [Agent Security Knowledge Check](https://mahsa-teimourikia.github.io/agent-security/quiz/) after completing the lessons.

## Curriculum

### Beginner

- Security foundations and threat modeling
- Tool policy, authorization, and approval
- Prompt injection and untrusted content
- Secure research-assistant capstone
- Secure research assistant: narrow tools, evidence, and policy boundaries

### Intermediate

- Identity propagation and memory security
- MCP gateway security
- Workflow policy and release gates
- Secure support-workflow scenarios
- Incident response, containment, idempotent recovery, and safe replay

### Advanced

- Security attack evaluation
- Multi-agent delegation and cascading failures
- Durable execution, rollback, and kill switches
- Production readiness and incident response
- Governance, release gates, autonomy measurement, and rollback drills

## Practical material

- [Security foundations](docs/security-foundations.md)
- [Tools, identity, and memory](docs/tools-identity-and-memory.md)
- [Prompt injection and MCP](docs/prompt-injection-and-mcp.md)
- [Production security and evaluation](docs/production-and-evaluation.md)
- [Python labs](labs/)
- [Notebook companions](labs/notebooks/)
- [Secure research agent capstone](docs/secure-agent-capstone.md)
- [Incident response and recovery](docs/incident-response-and-recovery.md)
- [Governance and production readiness](docs/governance-and-production-readiness.md)
- [Security tools and technologies](docs/security-tools-and-technologies.md) — tool selection guide, maintained documentation, and research papers

The core labs use only the Python standard library and deterministic fixtures. LangGraph and provider integrations are optional and should remain behind tested policy and evaluation boundaries.

## Security references

- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [OWASP Securing Agentic Applications Guide](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [Google Secure AI Framework](https://cloud.google.com/use-cases/secure-ai-framework)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [NSA MCP Security Design Considerations](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/)
- [Microsoft Agent Safety](https://learn.microsoft.com/en-us/agent-framework/agents/safety)
- [OpenAI Agents SDK human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/)

## Validation

```bash
python -m compileall labs
python -m json.tool labs/notebooks/01_tool_policy.ipynb >/dev/null
```

Learning with One+i · responsible AI, real-world impact — [oneplusi.io](https://oneplusi.io)
