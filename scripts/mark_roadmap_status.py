"""Keep every canonical roadmap README honest about its current evidence."""
from pathlib import Path
import re


PILOTS = {8, 9, 11, 13, 14, 16, 18, 25, 29, 30, 33, 36}
READING = set(range(1, 8))


for path in sorted(Path("curriculum").glob("*/*/README.md")):
    match = re.match(r"(\d{2})-", path.parent.name)
    if not match:
        continue
    number = int(match.group(1))
    # The published path restarts at 01 within each level. Canonical roadmap
    # folders use global 01–36 numbers and are uniquely identified by ranges.
    level = path.parts[1]
    canonical = (
        level == "beginner" and 1 <= number <= 7 and path.parent.name not in {"01-tool-policy", "02-prompt-injection", "03-secure-research-agent"}
    ) or (level == "intermediate" and 8 <= number <= 17) or (level == "advanced" and 18 <= number <= 27) or (level == "enterprise-agent" and 28 <= number <= 36)
    if not canonical:
        continue

    text = path.read_text()
    if "<!-- roadmap-status -->" in text:
        continue
    status = "Reading" if number in READING else "Pilot" if number in PILOTS else "Planned"
    if status == "Reading":
        detail = "The chapter is available; course-owned lab, notebook, tests, and checkpoint are still required."
    elif status == "Pilot":
        detail = "Some executable evidence exists; the remaining gate is listed in the Learning Hub and review plan."
    else:
        detail = "The release contract is defined; lab, notebook, tests, and checkpoint are still required."
    banner = f"\n\n<!-- roadmap-status -->\n> **Roadmap status: {status}.** {detail}\n"
    first_break = text.find("\n")
    path.write_text(text[:first_break] + banner + text[first_break + 1:])
    print(f"marked {number:02d} {status}: {path}")
