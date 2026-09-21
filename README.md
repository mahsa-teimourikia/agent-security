# Agent Security Learning Hub

A comprehensive, source-linked curriculum for securing AI agents, agentic workflows, tools, memory, protocols, and multi-agent systems.

## Start with the Learning Hub

**[Open the Agent Security Learning Hub →](https://mahsa-teimourikia.github.io/agent-security/)**

The Hub is organized into Foundation, Beginner, Intermediate, and Advanced published paths. Each published lesson follows **Learn → Lab → Checkpoint**, links to a credential-free notebook and reusable Python lab, uses a focused checkpoint, and records completion locally in the browser. Roadmap material is shown separately and cannot be marked complete before its runnable artifacts and evaluation are ready.

### Knowledge check

Ready to test your understanding? Take the interactive [Agent Security Knowledge Check](https://mahsa-teimourikia.github.io/agent-security/quiz/) after completing the lessons. It includes multi-select questions, explanations, scoring, and retry support.

## Published curriculum

### Foundation

| # | Title | Lab | Notebook |
|---|---|---|---|
| 01 | [Agent Security Architecture and Trust Boundaries](curriculum/roadmap/beginner/01-agent-security-architecture-and-trust-boundaries/README.md) | [lab.py](curriculum/roadmap/beginner/01-agent-security-architecture-and-trust-boundaries/lab.py) | [lab.ipynb](curriculum/roadmap/beginner/01-agent-security-architecture-and-trust-boundaries/lab.ipynb) |
| 02 | [Threat Modeling Agentic Systems](curriculum/roadmap/beginner/02-threat-modeling-agentic-systems/README.md) | [lab.py](curriculum/roadmap/beginner/02-threat-modeling-agentic-systems/lab.py) | [lab.ipynb](curriculum/roadmap/beginner/02-threat-modeling-agentic-systems/lab.ipynb) |

### Beginner

| # | Title | Lab | Notebook |
|---|---|---|---|
| 01 | [Security Foundations and Tool Policy](curriculum/beginner/01-tool-policy/README.md) | [01_tool_policy.py](curriculum/beginner/01-tool-policy/01_tool_policy.py) | [01_tool_policy.ipynb](curriculum/beginner/01-tool-policy/01_tool_policy.ipynb) |
| 02 | Prompt Injection and Untrusted Content | [02_prompt_injection.py](curriculum/beginner/02-prompt-injection/02_prompt_injection.py) | [02_prompt_injection.ipynb](curriculum/beginner/02-prompt-injection/02_prompt_injection.ipynb) |
| 03 | Secure Research Agent | [03_secure_research_agent.py](curriculum/beginner/03-secure-research-agent/03_secure_research_agent.py) | [03_secure_research_agent.ipynb](curriculum/beginner/03-secure-research-agent/03_secure_research_agent.ipynb) |

### Intermediate

| # | Title | Lab |
|---|---|---|
| 01 | Identity Propagation and Memory Security | [01_identity_propagation.py](curriculum/intermediate/01-identity-propagation/01_identity_propagation.py) |
| 02 | MCP Gateway Security | [02_mcp_gateway.py](curriculum/intermediate/02-mcp-gateway/02_mcp_gateway.py) |
| 03 | Incident Response and Recovery | [03_incident_recovery.py](curriculum/intermediate/03-incident-recovery/03_incident_recovery.py) |

### Advanced

| # | Title | Lab |
|---|---|---|
| 01 | Security Attack Evaluation | [01_attack_evaluation.py](curriculum/advanced/01-attack-evaluation/01_attack_evaluation.py) |
| 02 | Multi-Agent Delegation and Security | [02_multi_agent_security.py](curriculum/advanced/02-multi-agent-security/02_multi_agent_security.py) |
| 03 | Governance and Production Readiness | [03_production_gate.py](curriculum/advanced/03-production-gate/03_production_gate.py) |

## 36-course expansion roadmap

The [AI Agent Security Engineering expansion map](curriculum/README.md) grows the published path across state and identity, execution and egress, MCP/A2A and multi-agent security, runtime assurance, incident operations, governance, and enterprise architecture. The Learning Hub lists each course’s current status and the exact gate remaining before publication.

Roadmap pages are intentionally labelled as reading sequences or pilot labs. A roadmap entry becomes published only when its chapter, credential-free notebook, reusable lab, failure injection, evaluation, production guidance, and focused checkpoint run together.

## Running locally

The core labs use only the Python standard library and deterministic fixtures. No credentials, API keys, or cloud services are required.

```bash
# Run Lesson 01 scenario evaluation
python3 curriculum/beginner/01-tool-policy/01_tool_policy.py

# Run focused tests
python3 -m pytest -q

# Compile all Python
python3 -m compileall -q curriculum tests

# Run the guided notebook
jupyter notebook curriculum/beginner/01-tool-policy/01_tool_policy.ipynb

# Execute every credential-free notebook as CI does
python3 scripts/execute-notebooks.py --timeout 90
```

## Security references

- [OWASP Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- [OWASP Securing Agentic Applications Guide](https://genai.owasp.org/resource/securing-agentic-applications-guide-1-0/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative)
- [Google Secure AI Framework](https://cloud.google.com/use-cases/secure-ai-framework)
- [MCP Security Best Practices 2025-11-25](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [NSA MCP Security Design Considerations](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4496698/nsa-releases-security-design-considerations-for-ai-driven-automation-leveraging/)
- [Microsoft Agent Safety](https://learn.microsoft.com/en-us/agent-framework/agents/safety)
- [OpenAI Agents SDK human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/)

Learning with One+i · responsible AI, real-world impact — [oneplusi.io](https://oneplusi.io)
