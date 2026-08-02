"""Security release gate from deterministic attack cases."""
def release_gate(cases: list[dict]) -> dict:
    failed = [case["name"] for case in cases if case["attack_succeeded"] or not case["traceable"]]
    return {"ready": not failed, "failed_cases": failed}

if __name__ == "__main__":
    cases = [{"name":"injection","attack_succeeded":False,"traceable":True},{"name":"exfiltration","attack_succeeded":True,"traceable":True}]
    assert release_gate(cases) == {"ready": False, "failed_cases": ["exfiltration"]}
    assert release_gate([{"name":"safe","attack_succeeded":False,"traceable":True}])["ready"]
    print(release_gate(cases))
