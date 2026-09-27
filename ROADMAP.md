# Agent Security curriculum roadmap

The roadmap is managed as an evidence backlog rather than a list of pages.

## Current release

Thirteen published lessons form the runnable path:

- four foundation courses on architecture, threat modeling, security invariants,
  blast-radius control, and secure tool interfaces;
- three beginner courses on tool policy, prompt injection, and secure research;
- three intermediate courses on identity, MCP gateways, and incident recovery;
- three advanced courses on attack evaluation, delegation, and production
  readiness.

Every published entry must pass substantive README, lab, notebook, checkpoint,
test, link, and site-build checks. The Hub must never infer publication from a
directory or filename alone.

## Expansion sequence

The canonical [thirty-six-course map](curriculum/README.md) is delivered in
four stages:

1. Foundation F01–F07: boundaries, threats, invariants, tools, authorization,
   prompt injection, and evidence.
2. State and execution I01–I10: memory, durable state, identity, secrets,
   sandboxing, egress, tool results, RAG, MCP, and human approval.
3. Distributed adversaries A01–A10: delegation, cross-agent injection, cascades,
   A2A, protocol composition, supply chain, fuzzing, red teaming,
   observability, and hunting.
4. Enterprise operations E01–E09: long-running agents, kill switches, incidents,
   forensics, release gates, governance, architecture, review, and capstone.

The Learning Hub lists every course’s Reading, Pilot, or Planned state and its
remaining evidence. The [curriculum map](curriculum/README.md) is the canonical
sequence and links to every course page.

## Promotion rule

A roadmap course becomes Published only in the same change that delivers and
validates its course-specific capability statement, README, lab, notebook,
negative tests, checkpoint, Hub entry, and references. Prefer one complete
vertical slice over several new outlines. Protocol claims must pin current
versions, and every simulation must name its production replacement.
