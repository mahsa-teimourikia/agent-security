import json
from pathlib import Path

for path in Path("labs/notebooks").glob("*.ipynb"):
    data = json.loads(path.read_text())
    assert data.get("nbformat") == 4 and isinstance(data.get("cells"), list), path
print("notebooks valid")
