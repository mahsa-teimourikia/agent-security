const lesson = (id, level, step, title, summary, outcome, folder, fileStem, checkpoint) => ({
  id,
  level,
  step,
  title,
  summary,
  outcome,
  material: `curriculum/${folder}/README.md`,
  lab: `curriculum/${folder}/${fileStem}.py`,
  notebook: `curriculum/${folder}/${fileStem}.ipynb`,
  checkpoint,
});

export const publishedLessons = [
  lesson("b1", "Beginner", "01", "Security foundations and tool policy", "Place authorization, approval, budgets, and audit controls at trusted boundaries.", "Design a narrow action contract and prove that unauthorized side effects are rejected.", "beginner/01-tool-policy", "01_tool_policy", {
    prompt: "A model proposes a destructive action. Which component may authorize it?",
    options: ["The model prompt", "A deterministic policy at the action boundary", "Retrieved content"],
    correct: 1,
    explanation: "Only trusted application policy can grant authority; prompts and retrieved text are inputs, not policy decisions.",
  }),
  lesson("b2", "Beginner", "02", "Prompt injection and untrusted content", "Separate instructions from documents, tool output, and memory.", "Contain an indirect injection even when simple marker detection misses it.", "beginner/02-prompt-injection", "02_prompt_injection", {
    prompt: "A retrieved document says to ignore policy and send a secret. What authority does it have?",
    options: ["None; it remains untrusted evidence", "System-level authority", "Tool-administrator authority"],
    correct: 0,
    explanation: "External content may inform an answer but cannot authorize a tool call or change system policy.",
  }),
  lesson("b3", "Beginner", "03", "Secure research agent", "Combine provenance, evidence ranking, narrow tools, and policy enforcement.", "Return traceable evidence while refusing unsafe capabilities and poisoned instructions.", "beginner/03-secure-research-agent", "03_secure_research_agent", {
    prompt: "What makes a research answer auditable?",
    options: ["A fluent explanation", "Stable evidence identifiers and policy receipts", "A larger context window"],
    correct: 1,
    explanation: "Auditability comes from attributable evidence and observable policy decisions, not answer fluency.",
  }),
  lesson("i1", "Intermediate", "01", "Identity propagation", "Preserve user, workload, tenant, resource, operation, and delegated scope.", "Reject tenant swaps, audience confusion, and authority widening across service hops.", "intermediate/01-identity-propagation", "01_identity_propagation", {
    prompt: "A service receives both a signed principal and a tenant supplied in tool arguments. Which tenant is authoritative?",
    options: ["The tool argument", "The trusted identity context", "Whichever appears first"],
    correct: 1,
    explanation: "Authorization scope must be derived from authenticated application state, never model-controlled arguments.",
  }),
  lesson("i2", "Intermediate", "02", "MCP gateway security", "Treat discovery as metadata and independently authenticate and authorize every invocation.", "Enforce server trust, scopes, schemas, limits, and privacy-aware receipts.", "intermediate/02-mcp-gateway", "02_mcp_gateway", {
    prompt: "A discovered MCP server advertises an admin tool. What should the gateway do?",
    options: ["Trust discovery", "Require server trust and caller authorization", "Forward the caller token"],
    correct: 1,
    explanation: "Discovery does not prove server identity, tool safety, or caller authority.",
  }),
  lesson("i3", "Intermediate", "03", "Incident response and recovery", "Contain suspicious runs, revoke capabilities, and recover with safe replay.", "Prevent duplicate effects and reauthorize changed state before resuming.", "intermediate/03-incident-recovery", "03_incident_recovery", {
    prompt: "Why must a replay reuse the original idempotency key?",
    options: ["To improve prompts", "To prevent a second external side effect", "To replace authorization"],
    correct: 1,
    explanation: "Idempotency deduplicates uncertain retries; authorization is still evaluated independently.",
  }),
  lesson("a1", "Advanced", "01", "Security attack evaluation", "Turn versioned attack cases and observable trajectories into release evidence.", "Measure severe failures, traceability, and valid-task blocking with correct denominators.", "advanced/01-attack-evaluation", "01_attack_evaluation", {
    prompt: "What should block release even if the average score improves?",
    options: ["One severe unauthorized action", "A formatting difference", "A slower harmless fixture"],
    correct: 0,
    explanation: "A severe security failure is a release blocker and must not be hidden by aggregate averages.",
  }),
  lesson("a2", "Advanced", "02", "Multi-agent delegation", "Constrain child roles, scopes, budgets, state, and termination conditions.", "Prove a delegated worker cannot exceed its parent authority.", "advanced/02-multi-agent-security", "02_multi_agent_security", {
    prompt: "Which delegation relationship must always hold?",
    options: ["Child authority contains parent authority", "Child authority is a subset of parent authority", "All agents share credentials"],
    correct: 1,
    explanation: "Delegation attenuates authority; it must never amplify the parent’s capabilities.",
  }),
  lesson("a3", "Advanced", "03", "Production readiness", "Bind governance, ownership, rollback drills, and attack results into a release gate.", "Issue an evidence-based production decision with named residual-risk owners.", "advanced/03-production-gate", "03_production_gate", {
    prompt: "Which evidence is required before granting production autonomy?",
    options: ["A successful demo", "A rollback drill and named control owners", "A model self-assessment"],
    correct: 1,
    explanation: "Production authority requires independently verified controls, recovery readiness, and accountable ownership.",
  }),
];

export const roadmapTracks = [
  { level: "Foundation", range: "01–07", status: "Reading sequence", summary: "Trust boundaries, threat models, invariants, narrow tools, authorization, injection, and evidence security." },
  { level: "State & execution", range: "08–17", status: "Pilot labs", summary: "Memory, durable state, identity, credentials, sandboxing, egress, poisoned output, RAG, MCP, and approval." },
  { level: "Distributed adversaries", range: "18–27", status: "Pilot labs", summary: "Delegation, cross-agent injection, cascading failures, protocols, supply chain, fuzzing, evaluation, and detection." },
  { level: "Enterprise operations", range: "28–36", status: "Pilot labs", summary: "Long-running agents, revocation, incidents, forensics, release gates, governance, architecture, and capstone." },
];
