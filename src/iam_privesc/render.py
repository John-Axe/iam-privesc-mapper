"""Render the principal graph to PNG (graphviz) and Mermaid source (text)."""

from __future__ import annotations

import graphviz
import networkx as nx

NODE_COLOR = {"user": "#4f81bd", "role": "#9b59b6"}
EDGE_COLOR = {"assume_role": "#7f8c8d", "pass_role": "#7f8c8d", "escalation": "#e74c3c"}
EDGE_STYLE = {"assume_role": "solid", "pass_role": "dashed", "escalation": "bold"}


def render_png(graph: nx.DiGraph, output_path: str) -> str:
    """Render `graph` to `output_path` (a .png path) via graphviz. Returns the
    path actually written (graphviz appends the format extension itself)."""
    dot = graphviz.Digraph("iam_privesc", format="png")
    dot.attr(rankdir="LR", fontsize="10")

    # ARNs contain colons, which graphviz's edge() doesn't quote the way
    # node() does, producing invalid DOT syntax. Use synthetic node IDs
    # instead and keep the ARN/name as the label.
    node_ids = {node: f"n{i}" for i, node in enumerate(graph.nodes())}

    for node, data in graph.nodes(data=True):
        kind = data.get("kind", "user")
        dot.node(
            node_ids[node],
            label=data.get("label", node),
            shape="box" if kind == "role" else "ellipse",
            style="filled",
            fillcolor=NODE_COLOR.get(kind, "#bdc3c7"),
            fontcolor="white",
        )

    for u, v, data in graph.edges(data=True):
        kind = data.get("kind", "")
        dot.edge(
            node_ids[u],
            node_ids[v],
            label=data.get("label", ""),
            color=EDGE_COLOR.get(kind, "#34495e"),
            style=EDGE_STYLE.get(kind, "solid"),
            fontsize="8",
        )

    stem = output_path[:-4] if output_path.endswith(".png") else output_path
    return dot.render(filename=stem, cleanup=True)


def to_mermaid(graph: nx.DiGraph) -> str:
    lines = ["graph LR"]
    node_ids = {node: f"n{i}" for i, node in enumerate(graph.nodes())}

    for node, data in graph.nodes(data=True):
        kind = data.get("kind", "user")
        shape = f'["{data.get("label", node)}"]' if kind == "role" else f'(("{data.get("label", node)}"))'
        lines.append(f"    {node_ids[node]}{shape}")

    escalation_edges = []
    for idx, (u, v, data) in enumerate(graph.edges(data=True)):
        kind = data.get("kind", "")
        arrow = "-.->" if kind == "pass_role" else "-->"
        label = data.get("label", "")
        lines.append(f"    {node_ids[u]} {arrow}|{label}| {node_ids[v]}")
        if kind == "escalation":
            escalation_edges.append(idx)

    if escalation_edges:
        idxs = ",".join(str(i) for i in escalation_edges)
        lines.append(f"    linkStyle {idxs} stroke:#e74c3c,stroke-width:2px")

    return "\n".join(lines)
