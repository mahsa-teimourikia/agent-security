"""Risk-weighted release gate for a customer-support agent."""
REQUIRED = {"threat_model", "policy_tests", "attack_eval", "rollback_drill", "owner"}
WEIGHTS = {"threat_model": 3, "policy_tests": 3, "attack_eval": 3, "rollback_drill": 2, "owner": 1}

def release_gate(evidence: set[str]) -> tuple[bool, list[str]]:
    missing = sorted(REQUIRED - evidence)
    return not missing, missing

def risk_score(violations: int, tasks: int, interventions: int) -> dict:
    """Return interpretable release metrics; violations must be zero for launch."""
    return {"violation_rate": violations / max(tasks, 1), "intervention_rate": interventions / max(tasks, 1), "safe": violations == 0}

if __name__ == "__main__":
    assert release_gate(REQUIRED) == (True, [])
    assert release_gate({"threat_model", "owner"}) == (False, ["attack_eval", "policy_tests", "rollback_drill"])
    assert risk_score(0, 10, 2) == {"violation_rate": 0.0, "intervention_rate": 0.2, "safe": True}
    assert not risk_score(1, 10, 0)["safe"]
    print("release gate examples passed")
