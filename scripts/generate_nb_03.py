"""Compatibility validator for the hand-maintained Beginner 03 notebook.

The old version of this script embedded a second, stale copy of the notebook
and could overwrite the authorization-before-ranking lab. The notebook is now
the canonical source so course content, executable assertions, and cell IDs stay
together. Run this script to verify that the required learning stages exist.
"""

from __future__ import annotations

import json
from pathlib import Path


NOTEBOOK = Path("curriculum/beginner/03-secure-research-agent/03_secure_research_agent.ipynb")
REQUIRED_CELL_IDS = {
    "title",
    "pre-filter-code",
    "snapshot-code",
    "tenant-code",
    "injection-code",
    "citations-code",
    "audit-code",
    "sdk-code",
    "evaluation-code",
}


def main() -> None:
    notebook = json.loads(NOTEBOOK.read_text(encoding="utf-8"))
    if notebook.get("nbformat") != 4:
        raise ValueError(f"{NOTEBOOK}: expected notebook format 4")
    cell_ids = {cell.get("id") for cell in notebook.get("cells", [])}
    missing = REQUIRED_CELL_IDS - cell_ids
    if missing:
        raise ValueError(f"{NOTEBOOK}: missing required cells: {sorted(missing)}")
    if any(not cell.get("id") for cell in notebook["cells"]):
        raise ValueError(f"{NOTEBOOK}: every cell must have a stable ID")
    print(f"Validated {NOTEBOOK} ({len(notebook['cells'])} cells).")


if __name__ == "__main__":
    main()
