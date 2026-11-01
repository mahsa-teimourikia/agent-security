"""Run the Enterprise 01 credential-free security lab."""
from __future__ import annotations

from dataclasses import asdict
import json

from secure_long_running_agents import Decision, concurrent_resume_demo, evaluate_controls


def main() -> None:
    report = evaluate_controls()
    race = concurrent_resume_demo()
    assert report.valid_completion_rate == 1
    assert report.unsafe_resume_rate == 0
    assert report.stale_lease_use_rate == 0
    assert report.duplicate_effect_rate == 0
    assert report.orphan_detection_rate == 1
    assert report.safe_failure_rate == 1
    assert race.count(Decision.ALLOW) == 1
    print(json.dumps({"evaluation": asdict(report), "resume_race": [item.value for item in race]}, indent=2))


if __name__ == "__main__":
    main()
