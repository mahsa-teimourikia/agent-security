"""Credential-free tool policy lab: authorization lives outside the model."""
from dataclasses import dataclass

@dataclass(frozen=True)
class Request:
    subject: str
    tenant: str
    operation: str
    resource: str
    approved: bool = False

def authorize(request: Request) -> str:
    if request.operation not in {"read", "preview", "write"}:
        return "deny: operation is not allowlisted"
    if request.tenant != "tenant-a":
        return "deny: tenant boundary"
    if request.operation == "write" and not request.approved:
        return "pause: human approval required"
    return "allow"

if __name__ == "__main__":
    for request in (Request("user-1", "tenant-a", "read", "doc-1"), Request("user-1", "tenant-a", "write", "doc-1")):
        print(authorize(request))
