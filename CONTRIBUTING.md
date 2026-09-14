# Contributing to the agent-security curriculum

## Course workflow

1. Read the [course review and improvement plan](COURSE_REVIEW_AND_IMPROVEMENT_PLAN.md)
   and choose the next numbered release slice.
2. State one precise course capability before editing artifacts.
3. Build README, reusable `lab.py`, guided notebook, negative tests, and focused
   checkpoint as one system.
4. Keep synthetic examples credential-free and deterministic.
5. Update the Learning Hub registry only after the publication gate passes.

## Security teaching contract

Every implementation must preserve this separation:

```text
model proposes
trusted application validates and authorizes
constrained component persists or executes
independent evidence verifies the outcome
```

Do not use prompts, caller-provided identity fields, self-asserted approval,
Python dataclass types, or model explanations as trust boundaries. Make all
teaching simplifications explicit and name the production replacement.

Each security claim should map to a control and proof. Include safe behavior,
the primary attack, an indirect bypass attempt, an edge or failure case, and a
valid task that must remain usable. Report severe cases outside averages.

## Local validation

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[contributor]'
npm ci
PYTHONPATH=. .venv/bin/pytest -q
PYTHONPATH=. .venv/bin/python scripts/execute-notebooks.py --timeout 90
npm run test:pages
npm run test:quiz
npm run check:pages-links
```

Review the rendered Hub and rerun the full suite after the final edit. A file’s
existence is not publication evidence.
