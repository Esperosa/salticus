#!/usr/bin/env python3
"""Krok 14: vykreslí graf incidentu z JSON (`endpoint replay-jsonl --graph-out`) do PNG.

Kauzální hrany (spawned, connected) jsou plné, ostatní čárkované; popisky jsou jen jména souborů.
Použití: python -I tools/k14_graph_png.py graf.json vystup.png [titulek]
"""
import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import networkx as nx  # noqa: E402

COLORS = {"host": "#4c78a8", "user": "#f58518", "process": "#54a24b", "peer": "#e45756", "file": "#b279a2"}


def short(label):
    return label.replace("\\", "/").rsplit("/", 1)[-1][:28] or label[:28]


def main():
    src, dst = sys.argv[1], sys.argv[2]
    title = sys.argv[3] if len(sys.argv) > 3 else "Graf incidentu"
    g = json.load(open(src, encoding="utf-8"))
    G = nx.DiGraph()
    for n in g["nodes"].values():
        G.add_node(n["id"], kind=n["kind"], label=short(n["label"]), t=n["first_seen"])
    for e in g["edges"]:
        if e["from"] in G and e["to"] in G:
            G.add_edge(e["from"], e["to"], kind=e["kind"])
    # vrstvy podle hloubky kauzálního řetězce (od uzlů bez příchozích hran)
    depth = {}
    for n in nx.topological_sort(G) if nx.is_directed_acyclic_graph(G) else G.nodes:
        preds = list(G.predecessors(n))
        depth[n] = 1 + max([depth.get(p, 0) for p in preds], default=-1)
    for n in G.nodes:
        G.nodes[n]["layer"] = depth.get(n, 0)
    pos = nx.multipartite_layout(G, subset_key="layer", align="vertical")
    fig, ax = plt.subplots(figsize=(13, 7))
    kinds = [G.nodes[n]["kind"] for n in G.nodes]
    nx.draw_networkx_nodes(G, pos, node_color=[COLORS.get(k, "#999999") for k in kinds], node_size=900, ax=ax)
    solid = [(a, b) for a, b, d in G.edges(data=True) if d["kind"] in ("spawned", "connected")]
    dashed = [(a, b) for a, b, d in G.edges(data=True) if d["kind"] not in ("spawned", "connected")]
    nx.draw_networkx_edges(G, pos, edgelist=solid, arrows=True, width=1.8, ax=ax, node_size=900)
    nx.draw_networkx_edges(G, pos, edgelist=dashed, arrows=True, style="dashed", alpha=0.5, ax=ax, node_size=900)
    nx.draw_networkx_labels(G, pos, labels={n: G.nodes[n]["label"] for n in G.nodes}, font_size=7, ax=ax)
    handles = [plt.Line2D([0], [0], marker="o", color="w", markerfacecolor=c, markersize=10, label=k) for k, c in COLORS.items()]
    ax.legend(handles=handles, loc="lower left", fontsize=8)
    ax.set_title(title)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(dst, dpi=130)


main()
