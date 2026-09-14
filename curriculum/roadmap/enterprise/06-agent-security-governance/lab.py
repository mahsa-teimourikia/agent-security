"""Small deterministic agent-inventory validation exercise."""
REQUIRED = {"agent_id", "owner", "purpose", "risk", "model", "tools", "permissions", "memory", "data_classification", "autonomy", "security_tests", "last_review", "kill_switch_owner"}
VALID_RISK = {"low", "medium", "high"}

def validate_inventory(record: dict) -> dict:
    missing = sorted(REQUIRED - set(record))
    errors = []
    if record.get("risk") not in VALID_RISK: errors.append("risk")
    if record.get("autonomy") == "write" and not record.get("security_tests"): errors.append("write-autonomy-needs-tests")
    if record.get("autonomy") == "write" and not record.get("kill_switch_owner"): errors.append("write-autonomy-needs-kill-switch-owner")
    return {"valid": not missing and not errors, "missing": missing, "errors": errors}

if __name__ == "__main__":
    record = {"agent_id":"support-v1","owner":"support-platform","purpose":"draft and resolve cases","risk":"high","model":"provider/model","tools":["ticketing"],"permissions":["read","write"],"memory":"tenant-scoped","data_classification":"internal","autonomy":"write","security_tests":["attack-suite-v1"],"last_review":"2026-08-11","kill_switch_owner":"on-call"}
    assert validate_inventory(record)["valid"]
    assert not validate_inventory({**record, "security_tests": []})["valid"]
    print("inventory validation passed")
