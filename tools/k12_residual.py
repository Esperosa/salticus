#!/usr/bin/env python3
"""Krok 12: zbytky detekce po rodinach s oddelenim slepych utoku (visible_flows = 0).

Sloupce: n, detekce, detekce z utoku s viditelnymi toky (cil 100 %), a slepe,
a viditelne (zadny nalez, toky dorazily), b nezobrazeno (vc. duvodu `hidden`),
c neprip., c typ. Hlasi i pocet rodin nad 90 %, nad 95 % a na 100 % mezi pozorovatelnymi.
Pouziti: python tools/k12_residual.py --families TSV --arm DIR[,DIR] [--min-n 10] [--out FILE]
"""
import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import attacks, load, wilson  # noqa: E402
from soak_k9 import pc, read_families  # noqa: E402
from k11_diag import group  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--arm", required=True)
    ap.add_argument("--min-n", type=int, default=10)
    ap.add_argument("--out")
    args = ap.parse_args()
    table = read_families(args.families)
    rows = load(args.arm.split(","))
    fams = defaultdict(list)
    for _, a in attacks(rows):
        info = table.get(a["family"], {"category": "security"})
        if info["category"] == "security":
            fams[a["family"]].append(a)
    out = ["| rodina | n | detekce | z viditelných (Wilson) | a slepé | a viditelné | b nezobrazeno (důvody) | c nepřipsáno | c typ | do 100 % z viditelných |",
           "|---|---:|---:|---|---:|---:|---|---:|---:|---:|"]
    vis_rates = []
    for f in sorted(fams, key=lambda k: -len(fams[k])):
        items = fams[f]
        if len(items) < args.min_n:
            continue
        info = table[f]
        g = Counter()
        hidden = Counter()
        for a in items:
            k = group(a, info)
            if k == "a":
                k = "a_slepe" if (a.get("diag") or {}).get("visible_flows", 1) == 0 else "a_vid"
            g[k] += 1
            if k == "b_nezobrazeno":
                for reason, v in ((a.get("diag") or {}).get("hidden") or {}).items():
                    hidden[reason] += v
        n = len(items)
        hit = sum(1 for a in items if a["cf"])
        vis = n - g["a_slepe"]
        p, lo, hi = wilson(hit, max(vis, 1))
        vis_rates.append(hit / max(vis, 1))
        hid = ", ".join(f"{k} {v}" for k, v in hidden.most_common(3)) or "-"
        out.append(f"| {f} | {n} | {pc(hit / n)} | {pc(p)} ({pc(lo)} až {pc(hi)}) | {g['a_slepe']} | {g['a_vid']} | {g['b_nezobrazeno']} ({hid}) | {g['c_neprip']} | {g['c_typ']} | {pc(1 - p)} |")
    out.append("")
    out.append(f"Rodin (n ≥ {args.min_n}): {len(vis_rates)}; z viditelných útoků nad 90 %: {sum(r >= .9 for r in vis_rates)}, nad 95 %: {sum(r >= .95 for r in vis_rates)}, na 100 %: {sum(r >= 1.0 for r in vis_rates)}.")
    text = "\n".join(out)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
