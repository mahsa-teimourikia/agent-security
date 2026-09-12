"""Deterministic URL admission policy; it never performs a network request."""
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


@dataclass(frozen=True)
class FetchPolicy:
    allow_hosts: frozenset[str]
    max_redirects: int = 2
    max_bytes: int = 1_000_000
    timeout_seconds: float = 3.0


def allowed_url(url: str, policy: FetchPolicy, *, resolved_ip: str, redirects: int = 0) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return {"allow": False, "reason": "scheme-or-authority"}
    if redirects > policy.max_redirects:
        return {"allow": False, "reason": "redirect-limit"}
    if host not in policy.allow_hosts:
        return {"allow": False, "reason": "host-allowlist"}
    try:
        candidate = ip_address(resolved_ip)
    except ValueError:
        return {"allow": False, "reason": "invalid-resolved-address"}
    if not candidate.is_global:
        return {"allow": False, "reason": "resolved-non-global-address"}
    return {"allow": True, "reason": "allow", "destination": host,
            "max_bytes": policy.max_bytes, "timeout_seconds": policy.timeout_seconds}


if __name__ == "__main__":
    policy = FetchPolicy(frozenset({"api.example.test"}))
    assert not allowed_url("http://api.example.test/policy", policy, resolved_ip="8.8.8.8")["allow"]
    assert not allowed_url("https://localhost/admin", policy, resolved_ip="127.0.0.1")["allow"]
    assert not allowed_url("https://api.example.test/policy", policy, resolved_ip="127.0.0.1")["allow"]
    assert allowed_url("https://api.example.test/policy", policy, resolved_ip="8.8.8.8")["allow"]
    print("URL policy attack cases passed")
