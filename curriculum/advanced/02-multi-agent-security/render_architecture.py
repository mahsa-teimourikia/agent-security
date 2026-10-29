"""Validate the delegation layout and render its SVG deterministically."""

from __future__ import annotations

from html import escape
import json
from pathlib import Path


ROOT = Path(__file__).parent


def _port_point(node: dict, port_name: str) -> tuple[float, float]:
    bounds = node["bounds"]
    port = node["ports"][port_name]
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


def _overlap(first: dict, second: dict) -> bool:
    return not (
        first["x"] + first["width"] <= second["x"]
        or second["x"] + second["width"] <= first["x"]
        or first["y"] + first["height"] <= second["y"]
        or second["y"] + second["height"] <= first["y"]
    )


def validate(specification: dict) -> None:
    if specification.get("version") != 1:
        raise ValueError("unsupported diagram-spec version")
    nodes = {node["id"]: node for node in specification["nodes"]}
    groups = {group["id"]: group for group in specification["groups"]}
    if len(nodes) != len(specification["nodes"]):
        raise ValueError("node IDs must be unique")

    node_list = list(nodes.values())
    for index, node in enumerate(node_list):
        if node["group"] not in groups:
            raise ValueError(f"unknown group for {node['id']}")
        bounds = node["bounds"]
        group = groups[node["group"]]["bounds"]
        if not (
            bounds["x"] >= group["x"]
            and bounds["y"] >= group["y"]
            and bounds["x"] + bounds["width"] <= group["x"] + group["width"]
            and bounds["y"] + bounds["height"] <= group["y"] + group["height"]
        ):
            raise ValueError(f"node outside group: {node['id']}")
        for other in node_list[index + 1 :]:
            if _overlap(bounds, other["bounds"]):
                raise ValueError(f"overlapping nodes: {node['id']} and {other['id']}")

    edge_ids: set[str] = set()
    for edge in specification["edges"]:
        if edge["id"] in edge_ids:
            raise ValueError(f"duplicate edge ID: {edge['id']}")
        edge_ids.add(edge["id"])
        source = nodes[edge["from"]["node"]]
        target = nodes[edge["to"]["node"]]
        start = _port_point(source, edge["from"]["port"])
        end = _port_point(target, edge["to"]["port"])
        route = edge["route"]
        attached = all(abs(actual - expected) <= 1 for actual, expected in zip(route[0], start))
        attached = attached and all(
            abs(actual - expected) <= 1 for actual, expected in zip(route[-1], end)
        )
        if not attached:
            raise ValueError(f"route is not attached to declared ports: {edge['id']}")
        if any(a[0] != b[0] and a[1] != b[1] for a, b in zip(route, route[1:])):
            raise ValueError(f"route must be orthogonal: {edge['id']}")


def _route(points: list[list[int]]) -> str:
    commands = [f"M{points[0][0]} {points[0][1]}"]
    for previous, current in zip(points, points[1:]):
        if current[1] == previous[1]:
            commands.append(f"H{current[0]}")
        elif current[0] == previous[0]:
            commands.append(f"V{current[1]}")
        else:
            commands.append(f"L{current[0]} {current[1]}")
    return " ".join(commands)


def render(specification: dict) -> str:
    validate(specification)
    canvas = specification["canvas"]
    colors = specification["style"]["semantic_colors"]
    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas["width"]}" height="{canvas["height"]}" viewBox="0 0 {canvas["width"]} {canvas["height"]}" role="img" aria-labelledby="title desc">',
        f'  <title id="title">{escape(specification["title"])}</title>',
        f'  <desc id="desc">{escape(specification["output"]["alt_text"])}</desc>',
        "  <defs>",
        '    <marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L8,4 L0,8 z" fill="#16324F"/></marker>',
        "    <style>.title{font:700 30px Inter,Arial,sans-serif;fill:#16324F}.subtitle{font:400 16px Inter,Arial,sans-serif;fill:#52606D}.group-label{font:700 17px Inter,Arial,sans-serif;fill:#16324F}.node-title{font:700 18px Inter,Arial,sans-serif;fill:#16324F}.node-sub{font:400 14px Inter,Arial,sans-serif;fill:#52606D}.edge-label{font:600 13px Inter,Arial,sans-serif;fill:#52606D}.edge{fill:none;stroke:#16324F;stroke-width:2.2;marker-end:url(#arrow)}.secondary{stroke:#7667E8;stroke-dasharray:7 5}</style>",
        "  </defs>",
        f'  <rect width="{canvas["width"]}" height="{canvas["height"]}" fill="{canvas["background"]}"/>',
        f'  <text x="64" y="55" class="title">{escape(specification["title"])}</text>',
        '  <text x="64" y="82" class="subtitle">Routing proposes. Trusted application code authenticates, attenuates, authorizes, admits, and records.</text>',
    ]

    for group in specification["groups"]:
        bounds = group["bounds"]
        lines.extend(
            [
                f'  <rect x="{bounds["x"]}" y="{bounds["y"]}" width="{bounds["width"]}" height="{bounds["height"]}" rx="18" fill="{group["fill"]}" stroke="{group["stroke"]}" stroke-width="2"/>',
                f'  <text x="{bounds["x"] + 24}" y="{bounds["y"] + 34}" class="group-label">{escape(group["label"])}</text>',
            ]
        )

    for edge in specification["edges"]:
        css = "edge secondary" if edge["kind"] == "secondary" else "edge"
        lines.append(f'  <path class="{css}" d="{_route(edge["route"])}"/>')

    for node in specification["nodes"]:
        bounds = node["bounds"]
        style = colors[node["type"]]
        center_x = bounds["x"] + bounds["width"] / 2
        subtitle_lines = node.get("subtitle_lines", [node["subtitle"]])
        title_y = bounds["y"] + bounds["height"] / 2 - 9 * len(subtitle_lines) + 1
        lines.append(
            f'  <rect x="{bounds["x"]}" y="{bounds["y"]}" width="{bounds["width"]}" height="{bounds["height"]}" rx="14" fill="{style["fill"]}" stroke="{style["stroke"]}" stroke-width="2"/>'
        )
        lines.append(
            f'  <text x="{center_x:g}" y="{title_y:g}" text-anchor="middle" class="node-title">{escape(node["label"])}</text>'
        )
        for index, subtitle in enumerate(subtitle_lines):
            lines.append(
                f'  <text x="{center_x:g}" y="{title_y + 28 + index * 24:g}" text-anchor="middle" class="node-sub">{escape(subtitle)}</text>'
            )

    for edge in specification["edges"]:
        bounds = edge["label_bounds"]
        lines.extend(
            [
                f'  <rect x="{bounds["x"]}" y="{bounds["y"]}" width="{bounds["width"]}" height="{bounds["height"]}" rx="5" fill="{canvas["background"]}"/>',
                f'  <text x="{bounds["x"] + bounds["width"] / 2:g}" y="{bounds["y"] + 15}" text-anchor="middle" class="edge-label">{escape(edge["label"])}</text>',
            ]
        )

    lines.extend(
        [
            '  <g transform="translate(64 842)">',
            '    <rect width="1472" height="34" rx="8" fill="#FFFFFF" stroke="#D7DEE8"/>',
            '    <circle cx="24" cy="17" r="6" fill="#7667E8"/><text x="38" y="22" class="node-sub">model/framework</text>',
            '    <circle cx="190" cy="17" r="6" fill="#2F6BFF"/><text x="204" y="22" class="node-sub">trusted control</text>',
            '    <circle cx="348" cy="17" r="6" fill="#F59E42"/><text x="362" y="22" class="node-sub">effect boundary</text>',
            '    <circle cx="515" cy="17" r="6" fill="#16A3A5"/><text x="529" y="22" class="node-sub">data/artifact</text>',
            '    <text x="1446" y="22" text-anchor="end" class="node-sub">Envelope is a ceiling; current application policy authorizes each use.</text>',
            "  </g>",
            "</svg>",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    specification = json.loads((ROOT / "architecture-spec.json").read_text())
    output = ROOT / specification["output"]["svg"]
    output.write_text(render(specification))
    print(f"validated {specification['id']} and rendered {output.name}")


if __name__ == "__main__":
    main()
