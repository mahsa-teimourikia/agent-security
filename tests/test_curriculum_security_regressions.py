"""Regression tests for the hardened curriculum examples."""

from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).parents[1]


def load_module(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_credential_scope_validation_is_explicit() -> None:
    secrets = load_module(
        "secrets_course_lab",
        "curriculum/roadmap/intermediate/04-secrets-and-credential-security/lab.py",
    )
    with pytest.raises(ValueError, match="unsupported credential scopes"):
        secrets.issue(
            "agent",
            "north",
            "ticket-api",
            frozenset({"admin", "delete_all"}),
            now=datetime.now(timezone.utc),
        )


def test_capstone_rejects_empty_or_unreported_evidence() -> None:
    capstone = load_module(
        "capstone_course_lab",
        "curriculum/roadmap/enterprise/09-production-secure-agent-capstone/lab.py",
    )
    empty = {key: "" for key in capstone.REQUIRED_DOSSIER}
    empty["controls"] = {name: "" for name in capstone.REQUIRED_CONTROLS}
    empty["production_decision"] = "approve"
    decision = capstone.assess(empty)
    assert not decision["ready"]
    assert "severe_attack_successes" in decision["invalid"]
    assert "control-evidence" in decision["invalid"]
