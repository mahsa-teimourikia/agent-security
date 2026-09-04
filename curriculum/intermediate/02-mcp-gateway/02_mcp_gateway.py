"""Mock MCP gateway: authenticate, scope, rate-limit, and audit tool calls."""
def dispatch(client: str, tool: str, scopes: set[str], calls: int, limit: int = 3) -> dict:
    if client not in {"trusted-client"}: return {"status":"deny", "reason":"client authentication"}
    if tool not in scopes: return {"status":"deny", "reason":"scope"}
    if calls >= limit: return {"status":"deny", "reason":"rate limit"}
    return {"status":"allow", "audit":{"client":client,"tool":tool}}

if __name__ == "__main__":
    assert dispatch("trusted-client", "search", {"search"}, 0)["status"] == "allow"
    assert dispatch("unknown", "search", {"search"}, 0)["status"] == "deny"
    assert dispatch("trusted-client", "delete", {"search"}, 0)["status"] == "deny"
    assert dispatch("trusted-client", "search", {"search"}, 3)["status"] == "deny"
    print(dispatch("trusted-client", "search", {"search"}, 0))
