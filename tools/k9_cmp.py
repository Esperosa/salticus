#!/usr/bin/env python3
"""Rychle srovnani dvou ramen po vzorech chovani a po rodinach (pomocny nastroj kroku 9)."""
import sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soak_k9 as k
from soak_coverage import load, wilson

def main():
    fam = k.read_families(sys.argv[1])
    arms = [a.split("=", 1) for a in sys.argv[2:]]
    data = {}
    for name, dirs in arms:
        rows = load(dirs.split(","))
        text, per = k.render(name, rows, fam)
        data[name] = (rows, per, k.totals(rows))
    for name, (rows, per, t) in data.items():
        d = max(t["days"], 1e-9)
        print(f"{name}: sit {t['nets']} utoku {t['n']} detekce {100*t['hit']/max(t['n'],1):.1f} FP/den {t['fp']/d:.2f} zobrazeno/den {t['shown']/d:.1f} omylem {t['wrong']}")
    pats = {}
    for name, (rows, per, t) in data.items():
        agg = {}
        for lab, r in per.items():
            p = r["info"].get("pattern") or "base"
            a = agg.setdefault(p, [0, 0, 0]); a[0] += r["n"]; a[1] += r["hit"]; a[2] += r["typed"]
        pats[name] = agg
    names = list(data)
    keys = sorted(set().union(*[set(v) for v in pats.values()]))
    print("vzor " + " ".join(f"{n}(n,det,typ)" for n in names))
    for p in keys:
        cells = []
        for n in names:
            a = pats[n].get(p, [0, 0, 0])
            cells.append(f"{a[0]:4d} {100*a[1]/max(a[0],1):5.1f} {100*a[2]/max(a[0],1):5.1f}")
        print(f"{p:10s} " + " | ".join(cells))
    # po rodinach: nejvetsi zmeny
    if len(names) == 2:
        a, b = data[names[0]][1], data[names[1]][1]
        diffs = []
        for lab in a:
            if lab in b and a[lab]["n"] >= 8:
                da = a[lab]["hit"] / a[lab]["n"]; db = b[lab]["hit"] / b[lab]["n"]
                diffs.append((db - da, lab, a[lab]["n"], da, db))
        diffs.sort()
        print("nejvetsi zhorseni:")
        for d in diffs[:6]: print(f"  {d[1]} n={d[2]} {100*d[3]:.0f}->{100*d[4]:.0f}")
        print("nejvetsi zlepseni:")
        for d in diffs[-10:]: print(f"  {d[1]} n={d[2]} {100*d[3]:.0f}->{100*d[4]:.0f}")

main()
