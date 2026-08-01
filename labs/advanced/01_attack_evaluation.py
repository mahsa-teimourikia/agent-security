"""Security release gate from deterministic attack cases."""
def release_gate(cases: list[dict]) -> dict:
    failed = [case["name"] for case in cases if case["attack_succeeded"] or not case["traceable"]]
    return {"ready": not failed, "failed_cases": failed}

if __name__ == "__main__":
    print(release_gate([{"name":"injection","attack_succeeded":False,"traceable":True},{"name":"exfiltration","attack_succeeded":True,"traceable":True}]))
