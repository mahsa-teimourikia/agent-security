"""Propagate identity and down-scoped permissions to a backend tool."""
def authorize(user: dict, agent: dict, resource: str, operation: str) -> dict:
    if user["tenant"] != agent["tenant"]:
        return {"allowed": False, "reason": "tenant mismatch"}
    if operation not in agent["allowed_operations"]:
        return {"allowed": False, "reason": "agent scope"}
    return {"allowed": resource in user["resources"], "principal": user["id"], "tenant": user["tenant"]}

if __name__ == "__main__":
    print(authorize({"id":"u1","tenant":"a","resources":["doc-1"]},{"tenant":"a","allowed_operations":["read"]},"doc-1","read"))
