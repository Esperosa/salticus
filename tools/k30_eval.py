#!/usr/bin/env python3
"""Vyhodnocení kroku 30 podle docs/diplomka/eval/predreg-krok30.md (H1, H2, H3, forenzní rozbor)."""
import json, math, sys
from math import comb

SCEN = [43, 44, 45, 46, 47, 48, 49, 50, 52, 53]
DIR = sys.argv[1] if len(sys.argv) > 1 else "F:/work-tmp/shadow/ctu"


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0, c - h), min(1, c + h)


def cause(s):
    if s["flows_in_scope"] == 0:
        return "mimo rozsah"
    if not s["mentioned_any"]:
        return "bez nálezu"
    if s["closed"]:
        return "uzavřeno"
    if s["suppressed_only"]:
        return "potlačeno"
    if s["unexpected_only"]:
        return "jen neočekávaný provoz"
    return "jiné"


tot = {"A": [0, 0, 0], "B": [0, 0, 0]}  # zachyceno, infikováno, zobrazeno
loss = gain = 0
print(f"{'scénář':8}{'infik.':>7}{'A zach.':>9}{'B zach.':>9}{'A zobr.':>9}{'B zobr.':>9}")
miss = []
for s in SCEN:
    a = json.load(open(f"{DIR}/test{s}_A.json", encoding="utf-8"))
    b = json.load(open(f"{DIR}/test{s}_B.json", encoding="utf-8"))
    ga = sum(1 for h in a["hosts"].values() if h["credited"])
    gb = sum(1 for h in b["hosts"].values() if h["credited"])
    n = a["infected"]
    print(f"{s:<8}{n:>7}{ga:>9}{gb:>9}{a['displayed_total']:>9}{b['displayed_total']:>9}")
    for arm, r, g in (("A", a, ga), ("B", b, gb)):
        tot[arm][0] += g
        tot[arm][1] += n
        tot[arm][2] += r["displayed_total"]
    loss += gb < ga
    gain += gb > ga
    for ip, h in b["hosts"].items():
        if not h["credited"]:
            miss.append((s, ip, cause(h), h["flows_in_scope"], h["mentioned_any"]))
print()
for arm in "AB":
    g, n, d = tot[arm]
    lo, hi = wilson(g, n)
    print(f"rameno {arm}: zachyceno {g}/{n} [{lo:.2f}, {hi:.2f}], zobrazeno celkem {d}")
ratio = tot["B"][2] / tot["A"][2]
print(f"H1 (B<A ve scénářích): {loss} z {len(SCEN)} -> {'SPLNĚNO' if loss == 0 else 'NESPLNĚNO'}")
print(f"H2 (zobrazeno B/A): {ratio:.3f} -> {'SPLNĚNO' if ratio <= 1.5 else 'NESPLNĚNO'}")
print(f"H3 (B>A ve scénářích): {gain} z {len(SCEN)}")
print("\nNezachycení v rameni B (forenzní kategorie):")
for s, ip, c, f, m in miss:
    print(f"  scénář {s} {ip}: {c}, toků v rozsahu {f}, zmíněn v nějakém nálezu: {m}")
