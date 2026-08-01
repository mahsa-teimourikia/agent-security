"""Deterministic incident containment and idempotent recovery example.

Scenario: a support agent is paused after a connector receives a suspicious
argument. The operator can investigate, revoke the connector, approve a safe
checkpoint, and replay an external side effect exactly once.
"""
from dataclasses import dataclass, field

@dataclass
class Run:
    run_id: str
    status: str = "active"
    events: list[str] = field(default_factory=list)
    committed_keys: set[str] = field(default_factory=set)
    revoked_tools: set[str] = field(default_factory=set)
    def pause(self, reason: str) -> None:
        self.status = "paused"; self.events.append(f"paused:{reason}")
    def revoke_tool(self, tool: str) -> None:
        self.revoked_tools.add(tool); self.events.append(f"revoked:{tool}")
    def commit_once(self, key: str, operation: str, tool: str = "ticketing") -> bool:
        if self.status != "active" or key in self.committed_keys or tool in self.revoked_tools: return False
        self.committed_keys.add(key); self.events.append(f"committed:{operation}"); return True
    def resume(self) -> None:
        if self.status == "paused": self.status = "active"; self.events.append("resumed:approved")

if __name__ == "__main__":
    run = Run("demo-1"); run.pause("suspicious tool argument"); run.revoke_tool("ticketing")
    assert not run.commit_once("ticket-7", "close-ticket")
    run.revoked_tools.remove("ticketing")  # operator approved a rotated connector
    run.resume(); assert run.commit_once("ticket-7", "close-ticket")
    assert not run.commit_once("ticket-7", "close-ticket")
    assert "revoked:ticketing" in run.events
    print(run.events)
