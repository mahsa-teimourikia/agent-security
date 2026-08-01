"""Deterministic incident containment and idempotent recovery example."""
from dataclasses import dataclass, field

@dataclass
class Run:
    run_id: str
    status: str = "active"
    events: list[str] = field(default_factory=list)
    committed_keys: set[str] = field(default_factory=set)
    def pause(self, reason: str) -> None:
        self.status = "paused"; self.events.append(f"paused:{reason}")
    def commit_once(self, key: str, operation: str) -> bool:
        if self.status != "active" or key in self.committed_keys: return False
        self.committed_keys.add(key); self.events.append(f"committed:{operation}"); return True
    def resume(self) -> None:
        if self.status == "paused": self.status = "active"; self.events.append("resumed:approved")

if __name__ == "__main__":
    run = Run("demo-1"); run.pause("suspicious tool argument")
    assert not run.commit_once("ticket-7", "close-ticket")
    run.resume(); assert run.commit_once("ticket-7", "close-ticket")
    assert not run.commit_once("ticket-7", "close-ticket")
    print(run.events)
