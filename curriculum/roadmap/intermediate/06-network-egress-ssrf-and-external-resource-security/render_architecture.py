"""Validate the egress-boundary layout and render its SVG deterministically."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


ROOT = Path(__file__).parent
SHARED_RENDERER = ROOT.parents[1] / "beginner" / "07-context-and-evidence-security" / "render_architecture.py"
SPEC = importlib.util.spec_from_file_location("course_diagram_renderer", SHARED_RENDERER)
assert SPEC and SPEC.loader
RENDERER = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, RENDERER)
SPEC.loader.exec_module(RENDERER)


def _validate_ports(specification: dict) -> None:
    nodes = {node["id"]: node for node in specification["nodes"]}
    edge_ids: set[str] = set()
    for edge in specification["edges"]:
        if edge["id"] in edge_ids:
            raise ValueError(f"duplicate edge ID: {edge['id']}")
        edge_ids.add(edge["id"])
        if edge["from_port"] not in nodes[edge["from"]]["ports"]:
            raise ValueError(f"unknown source port: {edge['id']}")
        if edge["to_port"] not in nodes[edge["to"]]["ports"]:
            raise ValueError(f"unknown target port: {edge['id']}")


def main() -> None:
    specification = json.loads((ROOT / "architecture-spec.json").read_text())
    _validate_ports(specification)
    RENDERER.validate(specification)
    output = ROOT / specification["output"]["svg"]
    output.write_text(RENDERER.render(specification))
    print(f"validated {specification['id']} and rendered {output.name}")


if __name__ == "__main__":
    main()
