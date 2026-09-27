"""Validate architecture-spec.json and render architecture.svg deterministically."""
from __future__ import annotations

from html import escape
import json
from pathlib import Path
import textwrap


ROOT = Path(__file__).parent
SPEC_PATH = ROOT / "architecture-spec.json"


def bounds(item: dict) -> tuple[int, int, int, int]:
    return item["x"], item["y"], item["w"], item["h"]


def overlaps(first: dict, second: dict) -> bool:
    ax, ay, aw, ah = bounds(first)
    bx, by, bw, bh = bounds(second)
    return not (ax + aw <= bx or bx + bw <= ax or ay + ah <= by or by + bh <= ay)


def validate(spec: dict) -> None:
    groups = {item["id"]: item for item in spec["groups"]}
    nodes = {item["id"]: item for item in spec["nodes"]}
    if len(groups) != len(spec["groups"]) or len(nodes) != len(spec["nodes"]):
        raise ValueError("duplicate group or node ID")
    width, height = spec["canvas"]["width"], spec["canvas"]["height"]
    for item in [*groups.values(), *nodes.values()]:
        x, y, w, h = bounds(item)
        if min(x, y, w, h) < 0 or x + w > width or y + h > height:
            raise ValueError(f"outside canvas: {item['id']}")
    for node in nodes.values():
        group = groups.get(node["group"])
        if group is None:
            raise ValueError(f"unknown group: {node['id']}")
        x, y, w, h = bounds(node)
        gx, gy, gw, gh = bounds(group)
        if x < gx or y < gy or x + w > gx + gw or y + h > gy + gh:
            raise ValueError(f"node outside group: {node['id']}")
    for index, first in enumerate(spec["nodes"]):
        for second in spec["nodes"][index + 1:]:
            if first["group"] == second["group"] and overlaps(first, second):
                raise ValueError(f"overlap: {first['id']} and {second['id']}")
    for edge in spec["edges"]:
        if edge["from"] not in nodes or edge["to"] not in nodes:
            raise ValueError(f"unresolved edge: {edge}")
        for x, y in edge.get("points", []):
            if not (0 <= x <= width and 0 <= y <= height):
                raise ValueError(f"edge point outside canvas: {edge}")


def center(node: dict) -> tuple[float, float]:
    return node["x"] + node["w"] / 2, node["y"] + node["h"] / 2


def wrapped(value: str, width: int) -> list[str]:
    return textwrap.wrap(value, width=max(14, width // 8), break_long_words=False)


def render(spec: dict) -> str:
    nodes = {item["id"]: item for item in spec["nodes"]}
    colors = {
        "control": ("#EAF1FF", "#2F6BFF"),
        "untrusted": ("#F0EEFF", "#7667E8"),
        "state": ("#FFFFFF", "#52606D"),
        "decision": ("#E5F7F6", "#16A3A5"),
        "enforcement": ("#E5F7F6", "#0B7A75"),
    }
    strokes = {"control": "#2F6BFF", "untrusted": "#7667E8", "enforcement": "#0B7A75", "evidence": "#52606D"}
    canvas = spec["canvas"]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas["width"]}" height="{canvas["height"]}" viewBox="0 0 {canvas["width"]} {canvas["height"]}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(spec["title"])}</title>',
        f'<desc id="desc">{escape(spec["output"]["alt_text"])}</desc>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="context-stroke"/></marker></defs>',
        f'<rect width="100%" height="100%" fill="{canvas["background"]}"/>',
        f'<text x="45" y="55" font-family="Inter,Arial,sans-serif" font-size="30" font-weight="700" fill="#16324F">{escape(spec["title"])}</text>',
        f'<text x="45" y="91" font-family="Inter,Arial,sans-serif" font-size="16" fill="#52606D">{escape(spec["subtitle"])}</text>',
    ]
    for group in spec["groups"]:
        x, y, w, h = bounds(group)
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="18" fill="#FFFFFF" stroke="#D7DEE8" stroke-width="2"/>')
        parts.append(f'<text x="{x + 16}" y="{y + 32}" font-family="Inter,Arial,sans-serif" font-size="15" font-weight="700" fill="#16324F">{escape(group["label"])}</text>')
    for edge in spec["edges"]:
        source, target = nodes[edge["from"]], nodes[edge["to"]]
        sx, sy = center(source)
        tx, ty = center(target)
        color = strokes[edge["kind"]]
        dash = ' stroke-dasharray="7 5"' if edge["kind"] in {"untrusted", "evidence"} else ""
        if "points" in edge:
            points = " ".join(f"{x},{y}" for x, y in edge["points"])
        elif abs(tx - sx) >= abs(ty - sy):
            start_x = source["x"] + source["w"] if tx >= sx else source["x"]
            end_x = target["x"] if tx >= sx else target["x"] + target["w"]
            midpoint = (start_x + end_x) / 2
            points = f"{start_x},{sy} {midpoint},{sy} {midpoint},{ty} {end_x},{ty}"
        else:
            start_y = source["y"] + source["h"] if ty >= sy else source["y"]
            end_y = target["y"] if ty >= sy else target["y"] + target["h"]
            midpoint = (start_y + end_y) / 2
            points = f"{sx},{start_y} {sx},{midpoint} {tx},{midpoint} {tx},{end_y}"
        parts.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2.3" marker-end="url(#arrow)"{dash}/>')
        if label_at := edge.get("label_at"):
            label_x, label_y = label_at
            label_width = len(edge["label"]) * 6.5 + 12
            parts.append(f'<rect x="{label_x - label_width/2}" y="{label_y - 13}" width="{label_width}" height="18" rx="4" fill="#FFFFFF" fill-opacity="0.94"/>')
            parts.append(f'<text x="{label_x}" y="{label_y}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="11" font-weight="650" fill="{color}">{escape(edge["label"])}</text>')
    for node in spec["nodes"]:
        x, y, w, h = bounds(node)
        fill, stroke = colors[node["type"]]
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
        cursor = y + 31
        for line in wrapped(node["label"], w - 24):
            parts.append(f'<text x="{x + w/2}" y="{cursor}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="15" font-weight="700" fill="#16324F">{escape(line)}</text>')
            cursor += 19
        cursor += 5
        for line in wrapped(node["detail"], w - 24):
            parts.append(f'<text x="{x + w/2}" y="{cursor}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="12" fill="#52606D">{escape(line)}</text>')
            cursor += 16
    parts.append('<g font-family="Inter,Arial,sans-serif" font-size="12" fill="#52606D"><circle cx="50" cy="880" r="5" fill="#2F6BFF"/><text x="62" y="884">trusted control</text><circle cx="190" cy="880" r="5" fill="#7667E8"/><text x="202" y="884">untrusted data/proposal</text><circle cx="385" cy="880" r="5" fill="#16A3A5"/><text x="397" y="884">decision/enforcement</text></g>')
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
