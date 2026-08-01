"""Constrain delegation with parent authority, role contracts, and budgets."""
def delegate(parent: dict, child_role: str, operation: str) -> dict:
    if child_role not in parent["roles"]: return {"allowed":False,"reason":"role not delegated"}
    if operation not in parent["roles"][child_role]: return {"allowed":False,"reason":"operation outside parent scope"}
    return {"allowed":True,"effective_scope":parent["roles"][child_role]}

if __name__ == "__main__":
    print(delegate({"roles":{"researcher":{"search","read"}}}, "researcher", "read"))
