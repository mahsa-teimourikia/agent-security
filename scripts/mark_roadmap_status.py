"""Keep every canonical roadmap README honest about its current evidence."""
from pathlib import Path
import re


PILOTS = {
    "intermediate": {1, 2, 4, 6, 7, 9},
    "advanced": {1, 8},
    "enterprise": {2, 3, 6, 9},
}


for path in sorted(Path("curriculum/roadmap").glob("*/*/README.md")):
    match = re.match(r"(\d{2})-", path.parent.name)
    if not match:
        continue
    number = int(match.group(1))
    level = path.parts[2]

    text = path.read_text()
    status = "Reading" if level == "beginner" else "Pilot" if number in PILOTS[level] else "Planned"
    if status == "Reading":
        detail = "The chapter is available; course-owned lab, notebook, tests, and checkpoint are still required."
    elif status == "Pilot":
        detail = "Some executable evidence exists; the remaining gate is listed in the Learning Hub."
    else:
        detail = "The release contract is defined; lab, notebook, tests, and checkpoint are still required."
    status_block = f"<!-- roadmap-status -->\n> **Roadmap status: {status}.** {detail}"
    if "<!-- roadmap-status -->" in text:
        text = re.sub(
            r"<!-- roadmap-status -->\n> \*\*Roadmap status: .*?\*\*.*?(?=\n\n)",
            status_block,
            text,
            count=1,
        )
    else:
        first_break = text.find("\n")
        text = text[:first_break] + f"\n\n{status_block}\n" + text[first_break + 1:]
    path.write_text(text)
    print(f"marked {level} {number:02d} {status}: {path}")
