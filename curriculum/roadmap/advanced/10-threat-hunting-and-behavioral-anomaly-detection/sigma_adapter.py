"""Real pySigma 2 adapter for the Advanced 10 portable single-event rule.

pySigma parses and converts the rule. The course's multi-event, tenant-scoped
sequence correlations remain in ``threat_hunting.py`` and must be implemented
with a correlation-capable production backend.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sigma.backends.test import TextQueryTestBackend
from sigma.collection import SigmaCollection
from sigma.policy import SigmaPolicy


ROOT = Path(__file__).parent
RULE_PATH = ROOT / "agent_egress_drift.yml"


@dataclass(frozen=True)
class ParsedSigmaRule:
    title: str
    rule_id: str
    status: str
    level: str
    query: str


def parse_and_convert(path: Path = RULE_PATH) -> ParsedSigmaRule:
    """Parse with restrictive pySigma defaults and convert to a test query."""
    collection = SigmaCollection.from_yaml(path.read_text(), policy=SigmaPolicy())
    if len(collection.rules) != 1 or collection.errors:
        raise ValueError("expected exactly one valid Sigma rule")
    rule = collection.rules[0]
    queries = TextQueryTestBackend().convert(collection)
    if len(queries) != 1:
        raise ValueError("expected exactly one converted query")
    return ParsedSigmaRule(
        title=str(rule.title), rule_id=str(rule.id), status=str(rule.status),
        level=str(rule.level), query=queries[0],
    )


if __name__ == "__main__":
    print(parse_and_convert())
