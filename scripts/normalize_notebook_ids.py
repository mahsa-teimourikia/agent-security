"""Assign deterministic cell identifiers required by modern nbformat."""
from hashlib import sha256
import json
from pathlib import Path


for path in sorted(Path("curriculum").rglob("*.ipynb")):
    notebook = json.loads(path.read_text())
    changed = False
    for index, cell in enumerate(notebook["cells"]):
        if not cell.get("id"):
            digest = sha256(f"{path}:{index}".encode()).hexdigest()[:12]
            cell["id"] = f"cell-{digest}"
            changed = True
    if changed:
        path.write_text(json.dumps(notebook, indent=1, ensure_ascii=False) + "\n")
        print(f"normalized {path}")
