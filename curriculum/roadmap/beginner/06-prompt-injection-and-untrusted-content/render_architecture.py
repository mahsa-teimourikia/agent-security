"""Validate architecture-spec.json and render architecture.svg deterministically."""
from __future__ import annotations

from html import escape
import json
from pathlib import Path
import textwrap


ROOT = Path(__file__).parent
SPEC_PATH = ROOT / "architecture-spec.json"


def _bounds(item: dict) -> tuple[int, int, int, int]:
    return item["x"], item["y"], item["w"], item["h"]


def _overlap(first: dict, second: dict) -> bool:
    ax, ay, aw, ah = _bounds(first)
    bx, by, bw, bh = _bounds(second)
    return not (ax + aw <= bx or bx + bw <= ax or ay + ah <= by or by + bh <= ay)


def validate(spec: dict) -> None:
    groups = {item["id"]: item for item in spec["groups"]}
    nodes = {item["id"]: item for item in spec["nodes"]}
    if len(groups) != len(spec["groups"]) or len(nodes) != len(spec["nodes"]):
        raise ValueError("group and node IDs must be unique")
    width, height = spec["canvas"]["width"], spec["canvas"]["height"]
    for group in groups.values():
        x, y, w, h = _bounds(group)
        if min(x, y, w, h) < 0 or x + w > width or y + h > height:
            raise ValueError(f"group outside canvas: {group['id']}")
    for node in nodes.values():
        if node["group"] not in groups:
            raise ValueError(f"unknown group: {node['id']}")
        x, y, w, h = _bounds(node)
        gx, gy, gw, gh = _bounds(groups[node["group"]])
        if x < gx or y < gy or x + w > gx + gw or y + h > gy + gh:
            raise ValueError(f"node outside group: {node['id']}")
    for index, first in enumerate(spec["nodes"]):
        for second in spec["nodes"][index + 1 :]:
            if _overlap(first, second):
                raise ValueError(f"overlapping nodes: {first['id']} and {second['id']}")
    for edge in spec["edges"]:
        if edge["from"] not in nodes or edge["to"] not in nodes:
            raise ValueError(f"unresolved edge: {edge}")


def _lines(value: str, width: int) -> list[str]:
    return textwrap.wrap(value, width=max(12, width // 9), break_long_words=False)


def _center(node: dict) -> tuple[float, float]:
    return node["x"] + node["w"] / 2, node["y"] + node["h"] / 2


def render(spec: dict) -> str:
    canvas = spec["canvas"]
    colors = {
        "untrusted": ("#F0EEFF", "#7667E8"),
        "signal": ("#FFF1DF", "#F59E42"),
        "control": ("#EAF1FF", "#2F6BFF"),
        "state": ("#FFFFFF", "#52606D"),
        "decision": ("#E5F7F6", "#16A3A5"),
        "enforcement": ("#E5F7F6", "#16A3A5"),
    }
    strokes = {
        "primary": ("#2F6BFF", ""),
        "secondary": ("#52606D", ""),
        "untrusted": ("#7667E8", "7 5"),
        "signal": ("#F59E42", "5 4"),
        "feedback": ("#F59E42", "8 5"),
    }
    nodes = {item["id"]: item for item in spec["nodes"]}
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas["width"]}" height="{canvas["height"]}" viewBox="0 0 {canvas["width"]} {canvas["height"]}" role="img" aria-labelledby="title desc">',
        f'<title id="title">{escape(spec["title"])}</title>',
        f'<desc id="desc">{escape(spec["output"]["alt_text"])}</desc>',
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="context-stroke"/></marker></defs>',
        f'<rect width="100%" height="100%" fill="{canvas["background"]}"/>',
        f'<text x="50" y="66" font-family="Inter,Arial,sans-serif" font-size="31" font-weight="700" fill="#16324F">{escape(spec["title"])}</text>',
        f'<text x="50" y="105" font-family="Inter,Arial,sans-serif" font-size="17" fill="#52606D">{escape(spec["subtitle"])}</text>',
    ]
    for group in spec["groups"]:
        x, y, w, h = _bounds(group)
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="20" fill="#FFFFFF" stroke="#D7DEE8" stroke-width="2"/>')
        parts.append(f'<text x="{x + 18}" y="{y + 35}" font-family="Inter,Arial,sans-serif" font-size="17" font-weight="700" fill="#16324F">{escape(group["label"])}</text>')
    for edge in spec["edges"]:
        source, target = nodes[edge["from"]], nodes[edge["to"]]
        sx, sy = _center(source)
        tx, ty = _center(target)
        stroke, dash = strokes[edge["kind"]]
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        if abs(tx - sx) >= abs(ty - sy):
            start_x = source["x"] + source["w"] if tx >= sx else source["x"]
            end_x = target["x"] if tx >= sx else target["x"] + target["w"]
            mid_x = (start_x + end_x) / 2
            points = f"{start_x},{sy} {mid_x},{sy} {mid_x},{ty} {end_x},{ty}"
        else:
            start_y = source["y"] + source["h"] if ty >= sy else source["y"]
            end_y = target["y"] if ty >= sy else target["y"] + target["h"]
            mid_y = (start_y + end_y) / 2
            points = f"{sx},{start_y} {sx},{mid_y} {tx},{mid_y} {tx},{end_y}"
        parts.append(f'<polyline points="{points}" fill="none" stroke="{stroke}" stroke-width="2.5" marker-end="url(#arrow)"{dash_attr}/>')
        label_x, label_y = edge["label_at"]
        label_width = len(edge["label"]) * 7 + 12
        parts.append(f'<rect x="{label_x - label_width / 2}" y="{label_y - 14}" width="{label_width}" height="20" rx="5" fill="#FFFFFF" fill-opacity="0.94"/>')
        parts.append(f'<text x="{label_x}" y="{label_y}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="12" font-weight="650" fill="{stroke}">{escape(edge["label"])}</text>')
    for node in spec["nodes"]:
        x, y, w, h = _bounds(node)
        fill, stroke = colors[node["type"]]
        parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="15" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')
        label_lines = _lines(node["label"], w - 24)
        detail_lines = _lines(node["detail"], w - 22)
        cursor = y + 31
        for line in label_lines:
            parts.append(f'<text x="{x + w / 2}" y="{cursor}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="15" font-weight="700" fill="#16324F">{escape(line)}</text>')
            cursor += 19
        cursor += 7
        for line in detail_lines:
            parts.append(f'<text x="{x + w / 2}" y="{cursor}" text-anchor="middle" font-family="Inter,Arial,sans-serif" font-size="12" fill="#52606D">{escape(line)}</text>')
            cursor += 16
    parts.append('<g font-family="Inter,Arial,sans-serif" font-size="13" fill="#52606D"><circle cx="60" cy="835" r="6" fill="#7667E8"/><text x="74" y="840">untrusted content or proposal</text><circle cx="300" cy="835" r="6" fill="#F59E42"/><text x="314" y="840">fallible signal</text><circle cx="455" cy="835" r="6" fill="#2F6BFF"/><text x="469" y="840">trusted control flow</text><circle cx="655" cy="835" r="6" fill="#16A3A5"/><text x="669" y="840">decision and enforcement</text></g>')
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
