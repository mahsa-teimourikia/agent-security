# Agent Security Learning Hub

A comprehensive, source-linked curriculum for securing AI agents, agentic workflows, tools, memory, protocols, and multi-agent systems.

## Start with the Learning Hub

**[Open the Agent Security Learning Hub →](https://mahsa-teimourikia.github.io/agent-security/)**

The Hub is organized into Beginner, Intermediate, and Advanced paths. Each lesson follows **Learn → Lab → Checkpoint**, includes theory and references, links to runnable Python code and notebooks, and records completion locally in the browser.

### Knowledge check

Ready to test your understanding? Take the interactive [Agent Security Knowledge Check](https://mahsa-teimourikia.github.io/agent-security/quiz/) after completing the lessons. It includes multi-select questions, explanations, scoring, and retry support.

## Curriculum

### Beginner

| # | Title | Lab | Notebook |
|---|---|---|---|
| 01 | [Security Foundations and Tool Policy](curriculum/beginner/01-tool-policy/README.md) | [01_tool_policy.py](curriculum/beginner/01-tool-policy/01_tool_policy.py) | [01_tool_policy.ipynb](curriculum/beginner/01-tool-policy/01_tool_policy.ipynb) |
| 02 | Prompt Injection and Untrusted Content | [02_prompt_injection.py](curriculum/beginner/02-prompt-injection/02_prompt_injection.py) | — |
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

## Running locally

The core labs use only the Python standard library and deterministic fixtures. No credentials, API keys, or cloud services are required.

```bash
# Run Lesson 01 scenario evaluation
python3 curriculum/beginner/01-tool-policy/01_tool_policy.py

# Run focused tests
python3 -m pytest tests/test_tool_policy.py -v

# Compile all Python
python3 -m compileall -q curriculum tests

# Run the guided notebook
jupyter notebook curriculum/beginner/01-tool-policy/01_tool_policy.ipynb
```

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

Learning with One+i · responsible AI, real-world impact — [oneplusi.io](https://oneplusi.io)
