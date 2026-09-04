import argparse
from pathlib import Path
import nbformat
from nbclient import NotebookClient

parser = argparse.ArgumentParser()
parser.add_argument("--timeout", type=int, default=90)
parser.add_argument("--list", action="store_true")
args = parser.parse_args()

notebooks = list(Path("curriculum").rglob("*.ipynb"))
if not notebooks:
    print("No notebooks found.")
    raise SystemExit(1)

if args.list:
    for nb in notebooks:
        print(f"notebook: {nb}")
    raise SystemExit(0)

for idx, path in enumerate(notebooks, 1):
    print(f"[{idx}/{len(notebooks)}] execute {path}")
    nb = nbformat.read(path, as_version=4)
    client = NotebookClient(nb, timeout=args.timeout, kernel_name="python3", resources={"metadata": {"path": path.parent}})
    client.execute()

print(f"Successfully executed {len(notebooks)} notebooks.")
