"""Validate architecture-spec.json and render architecture.svg deterministically."""
from __future__ import annotations

from html import escape
import json
from pathlib import Path


ROOT = Path(__file__).parent
SPEC_PATH = ROOT / "architecture-spec.json"


def _port(node: dict, name: str) -> tuple[float, float]:
    port, bounds = node["ports"][name], node["bounds"]
    offset = port["offset"]
    if port["side"] == "left":
        return bounds["x"], bounds["y"] + bounds["height"] * offset
    if port["side"] == "right":
        return bounds["x"] + bounds["width"], bounds["y"] + bounds["height"] * offset
    if port["side"] == "top":
        return bounds["x"] + bounds["width"] * offset, bounds["y"]
    if port["side"] == "bottom":
        return bounds["x"] + bounds["width"] * offset, bounds["y"] + bounds["height"]
    raise ValueError(f"unknown port side: {port['side']}")


def _inside(inner: dict, outer: dict) -> bool:
    return inner["x"] >= outer["x"] and inner["y"] >= outer["y"] and inner["x"] + inner["width"] <= outer["x"] + outer["width"] and inner["y"] + inner["height"] <= outer["y"] + outer["height"]


def _overlap(first: dict, second: dict) -> bool:
    return not (first["x"] + first["width"] <= second["x"] or second["x"] + second["width"] <= first["x"] or first["y"] + first["height"] <= second["y"] or second["y"] + second["height"] <= first["y"])


def validate(spec: dict) -> None:
    canvas = spec["canvas"]
    groups = {item["id"]: item for item in spec["groups"]}
    nodes = {item["id"]: item for item in spec["nodes"]}
    edges = {item["id"]: item for item in spec["edges"]}
    if len(groups) != len(spec["groups"]) or len(nodes) != len(spec["nodes"]) or len(edges) != len(spec["edges"]):
        raise ValueError("group, node, and edge IDs must be unique")
    canvas_bounds = {"x": 0, "y": 0, "width": canvas["width"], "height": canvas["height"]}
    for group in groups.values():
        if not _inside(group["bounds"], canvas_bounds):
            raise ValueError(f"group outside canvas: {group['id']}")
    for node in nodes.values():
        if node["group"] not in groups or not _inside(node["bounds"], groups[node["group"]]["bounds"]):
            raise ValueError(f"node outside group: {node['id']}")
    for index, first in enumerate(spec["nodes"]):
        for second in spec["nodes"][index + 1:]:
            if _overlap(first["bounds"], second["bounds"]):
                raise ValueError(f"overlapping nodes: {first['id']} and {second['id']}")
    for edge in edges.values():
        source, target = nodes.get(edge["from"]["node"]), nodes.get(edge["to"]["node"])
        if not source or not target:
            raise ValueError(f"unknown edge endpoint: {edge['id']}")
        if edge["from"]["port"] not in source["ports"] or edge["to"]["port"] not in target["ports"]:
            raise ValueError(f"unknown edge port: {edge['id']}")
        route = [tuple(point) for point in edge["route"]]
        if route[0] != _port(source, edge["from"]["port"]) or route[-1] != _port(target, edge["to"]["port"]):
            raise ValueError(f"detached edge: {edge['id']}")
        if any(x1 != x2 and y1 != y2 for (x1, y1), (x2, y2) in zip(route, route[1:])):
            raise ValueError(f"non-orthogonal edge: {edge['id']}")


def _text_lines(label: str, width: int) -> list[str]:
    words, lines, current = label.split(), [], ""
    limit = max(12, width // 11)
    for word in words:
        candidate = f"{current} {word}".strip()
        if current and len(candidate) > limit:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def render(spec: dict) -> str:
    canvas, colors = spec["canvas"], spec["style"]["semantic_colors"]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas["width"]}" height="{canvas["height"]}" viewBox="0 0 {canvas["width"]} {canvas["height"]}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(spec["title"])}</title>',
        f'<desc id="desc">{escape(spec["output"]["alt_text"])}</desc>',
        '<defs><marker id="arrow-blue" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#2F6BFF"/></marker><marker id="arrow-slate" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#52606D"/></marker><marker id="arrow-purple" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#7667E8"/></marker></defs>',
        f'<rect width="100%" height="100%" fill="{canvas["background"]}"/>',
        f'<text x="60" y="72" font-family="Inter,Arial,sans-serif" font-size="32" font-weight="700" fill="#16324F">{escape(spec["title"])}</text>',
        f'<text x="60" y="108" font-family="Inter,Arial,sans-serif" font-size="17" fill="#52606D">{escape(spec["subtitle"])}</text>',
    ]
    for group in spec["groups"]:
        bounds = group["bounds"]
        parts.append(f'<rect x="{bounds["x"]}" y="{bounds["y"]}" width="{bounds["width"]}" height="{bounds["height"]}" rx="20" fill="{group["fill"]}" stroke="{group["stroke"]}" stroke-width="2"/>')
        parts.append(f'<text x="{bounds["x"] + 22}" y="{bounds["y"] + 36}" font-family="Inter,Arial,sans-serif" font-size="18" font-weight="700" fill="#16324F">{escape(group["label"])}</text>')
    styles = {"primary": ("#2F6BFF", "arrow-blue", ""), "secondary": ("#52606D", "arrow-slate", ""), "feedback": ("#52606D", "arrow-slate", "6 5"), "untrusted": ("#7667E8", "arrow-purple", "7 5")}
    for edge in spec["edges"]:
        stroke, marker, dash = styles[edge["kind"]]
        route = " ".join(f"{x},{y}" for x, y in edge["route"])
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        parts.append(f'<polyline points="{route}" fill="none" stroke="{stroke}" stroke-width="2.5" stroke-linejoin="round" marker-end="url(#{marker})"{dash_attr}/>')
        x, y = edge["label_at"]
        parts.append(f'<text x="{x}" y="{y}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="13" font-weight="650" fill="{stroke}">{escape(edge["label"])}</text>')
    for node in spec["nodes"]:
        bounds, color = node["bounds"], colors[node["type"]]
        parts.append(f'<rect x="{bounds["x"]}" y="{bounds["y"]}" width="{bounds["width"]}" height="{bounds["height"]}" rx="16" fill="{color["fill"]}" stroke="{color["stroke"]}" stroke-width="2"/>')
        lines = _text_lines(node["label"], bounds["width"] - 32)
        start_y = bounds["y"] + 35
        for index, line in enumerate(lines):
            parts.append(f'<text x="{bounds["x"] + bounds["width"] / 2}" y="{start_y + index * 21}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="16" font-weight="700" fill="#16324F">{escape(line)}</text>')
        subtitle_y = start_y + len(lines) * 21 + 8
        for index, line in enumerate(_text_lines(node.get("subtitle", ""), bounds["width"] - 28)):
            parts.append(f'<text x="{bounds["x"] + bounds["width"] / 2}" y="{subtitle_y + index * 18}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="13" fill="#52606D">{escape(line)}</text>')
    parts.append('<g font-family="Inter,Arial,sans-serif" font-size="13" fill="#52606D"><circle cx="70" cy="850" r="6" fill="#2F6BFF"/><text x="84" y="855">enforced flow</text><circle cx="220" cy="850" r="6" fill="#7667E8"/><text x="234" y="855">untrusted proposal or result</text><circle cx="460" cy="850" r="6" fill="#52606D"/><text x="474" y="855">trusted state or recovery</text><circle cx="690" cy="850" r="6" fill="#16A3A5"/><text x="704" y="855">admitted evidence</text></g>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main() -> None:
    spec = json.loads(SPEC_PATH.read_text())
    validate(spec)
    output = ROOT / spec["output"]["svg"]
    output.write_text(render(spec))
    print(f"validated {spec['id']} and rendered {output.name}")


if __name__ == "__main__":
    main()
