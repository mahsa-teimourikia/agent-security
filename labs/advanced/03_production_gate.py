"""Small release gate: every required security signal must be present."""
REQUIRED = {"threat_model", "policy_tests", "attack_eval", "rollback_drill", "owner"}

def release_gate(evidence: set[str]) -> tuple[bool, list[str]]:
    missing = sorted(REQUIRED - evidence)
    return not missing, missing

if __name__ == "__main__":
    assert release_gate(REQUIRED) == (True, [])
    assert release_gate({"threat_model", "owner"}) == (False, ["attack_eval", "policy_tests", "rollback_drill"])
    print("release gate examples passed")
