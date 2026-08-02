"""Propagate identity and down-scoped permissions to a backend tool."""
def authorize(user: dict, agent: dict, resource: str, operation: str) -> dict:
    if user["tenant"] != agent["tenant"]:
        return {"allowed": False, "reason": "tenant mismatch"}
    if operation not in agent["allowed_operations"]:
        return {"allowed": False, "reason": "agent scope"}
    return {"allowed": resource in user["resources"], "principal": user["id"], "tenant": user["tenant"]}

if __name__ == "__main__":
    user = {"id":"u1","tenant":"a","resources":["doc-1"]}
    agent = {"tenant":"a","allowed_operations":["read"]}
    assert authorize(user, agent, "doc-1", "read")["allowed"]
    assert not authorize(user, agent, "doc-2", "read")["allowed"]
    assert not authorize(user, {"tenant":"b","allowed_operations":["read"]}, "doc-1", "read")["allowed"]
    print(authorize(user, agent, "doc-1", "read"))
