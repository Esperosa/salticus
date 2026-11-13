#!/usr/bin/env python3
"""Tabulka pokryti kroku 9: technika ATT&CK -> rodina/varianta -> detektor -> vysledek.

Detektor = typ nalezu, ktery utok nejcasteji zachytil (kontrafaktualni pripsani).
Vstup: `--families TSV` (salticus-program soak families) a `--arm NAZEV DIR [DIR...]`.
Vystup: Markdown (jen standardni knihovna).
"""
import argparse
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import soak_k9 as k  # noqa: E402
from soak_coverage import attacks, load, wilson  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--arm", nargs="+", required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    table = k.read_families(args.families)
    rows = load(args.arm)
    by = defaultdict(list)
    for _, a in attacks(rows):
        by[a["family"]].append(a)
    lines = ["| technika | taktika | rodina nebo varianta | kategorie | n | detektor (nejčastější typ nálezu) | detekce % (Wilson) | stav |",
             "|---|---|---|---|---:|---|---|---|"]
    order = sorted(table, key=lambda l: (table[l]["category"], table[l]["attack"] or "~", l))
    for label in order:
        info = table[label]
        items = by.get(label, [])
        n = len(items)
        hit = sum(1 for a in items if a["cf"])
        types = Counter(t for a in items if a["cf"] for t in a.get("cf_types", []))
        det = ", ".join(f"{t} ({c})" for t, c in types.most_common(2)) or "-"
        if n == 0:
            res, st = "-", "nepokryto v běhu"
        else:
            res, st = k.ci(hit, n), k.status({"n": n, "hit": hit, "typed": sum(1 for a in items if a["cf"] and info["types"] & set(a.get("cf_types", [])))})
        lines.append(f"| {info['attack'] or '-'} | {info.get('tactic','')} | {label} | {info['category']} | {n} | {det} | {res} | {st} |")
    body = "\n".join(lines) + "\n"
    if args.out:
        open(args.out, "w", encoding="utf-8").write(body)
    else:
        print(body)


if __name__ == "__main__":
    main()
