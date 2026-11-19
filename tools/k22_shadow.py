#!/usr/bin/env python3
"""Krok 22 (B4, K22-5): tabulka hranice automatizace ze stínových lístků soaku.

Vstup: soubory `*.shadow.jsonl` (K22_SHADOW) jednoho ramene. Bere se jen faktický svět
(`world` = "None") a cykly od `--from-cycle` (výchozí 240 = dny 6 a 7 sedmidenního běhu).
Buňka = (druh pozitivního důkazu × typ nálezu). Omyl = pravda simulátoru `truth_cf` nebo
`truth_causal` (sjednocení). Hlásí n lístků, správná, omylem, horní mez Wilson 95 %, potřebný
objem pro n >= 381 (síťodny) a rozklad odmítnutí podle důvodu.

Pouziti: python -I tools/k22_shadow.py SOUBOR [SOUBOR ...] [--from-cycle 240] [--days 2] [--json OUT]
"""
import argparse
import json
import math
from collections import Counter, defaultdict

NEED = 381  # n s 0 omyly, aby horni mez Wilson 95 % < 1 % (plan-krok22.md 0.1)


def wilson_upper(k, n, z=1.959964):
    if n == 0:
        return float("nan")
    p = k / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + half) / den


def cell_of(rec):
    sh = rec["shadow"]
    if rec["ev"] == "context":
        kind = f"context:{rec['kind']}"
    else:
        kind = "+".join(sh.get("positive") or []) or "zadny"
        kind = f"zebrik:{kind}"
    return kind, rec["type"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--from-cycle", type=int, default=240)
    ap.add_argument("--days", type=float, default=2.0, help="merene dny na sit (pro objem)")
    ap.add_argument("--json")
    a = ap.parse_args()
    cells = defaultdict(lambda: Counter())
    refusals = Counter()
    nets = set()
    attacks_admitted = []
    for path in a.files:
        with open(path, encoding="utf-8") as h:
            for line in h:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("world") != "None":
                    continue
                nets.add((rec["seed"], rec["net"]))
                if rec["cycle"] < a.from_cycle:
                    continue
                cell = cell_of(rec)
                sh = rec["shadow"]
                wrong = bool(rec.get("truth_cf")) or bool(rec.get("truth_causal"))
                c = cells[cell]
                c["records"] += 1
                c["records_attack"] += wrong
                if sh["admitted"]:
                    c["n"] += 1
                    c["wrong"] += wrong
                    c["wrong_cf"] += bool(rec.get("truth_cf"))
                    c["wrong_causal"] += bool(rec.get("truth_causal"))
                    c["unknown"] += rec["ev"] == "ladder" and not rec.get("truth_known", True)
                    if wrong:
                        attacks_admitted.append(rec)
                else:
                    refusals[(rec["ev"], sh.get("refusal") or "?")] += 1
    net_days = len(nets) * a.days
    rows = []
    for (kind, typ), c in sorted(cells.items(), key=lambda kv: (-kv[1]["n"], kv[0])):
        n, k = c["n"], c["wrong"]
        rate = n / net_days if net_days else 0.0
        need = (NEED / rate) if rate > 0 and k == 0 else None
        rows.append({"kind": kind, "type": typ, "records": c["records"], "records_attack": c["records_attack"],
                     "n": n, "correct": n - k, "wrong": k, "wrong_cf": c["wrong_cf"],
                     "wrong_causal": c["wrong_causal"], "upper": wilson_upper(k, n),
                     "candidate": n > 0 and wilson_upper(k, n) < 0.01,
                     "per_net_day": rate, "net_days_for_381": need})
    print(f"site {len(nets)}, merene sitodny {net_days:g}, od cyklu {a.from_cycle}")
    print("| druh dukazu | typ nalezu | zaznamu (utok) | listku n | spravne | omylem (cf/pricinne) | horni mez | na sitoden | sitodnu pro 381 |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        up = "-" if r["n"] == 0 else f"{100 * r['upper']:.2f} %"
        need = "-" if r["net_days_for_381"] is None else f"{r['net_days_for_381']:.0f}"
        print(f"| {r['kind']} | {r['type']} | {r['records']} ({r['records_attack']}) | {r['n']} | {r['correct']} |"
              f" {r['wrong']} ({r['wrong_cf']}/{r['wrong_causal']}) | {up} | {r['per_net_day']:.3f} | {need} |")
    print("\nodmitnuti podle duvodu:")
    for (ev, reason), v in refusals.most_common():
        print(f"  {ev:8s} {v:7d}  {reason}")
    print(f"\nlistky na utoku: {len(attacks_admitted)}")
    for rec in attacks_admitted[:20]:
        print("  ", rec["ev"], rec["seed"], rec["net"], rec["cycle"], rec["type"], rec.get("kind"),
              rec.get("key"), "cf" if rec.get("truth_cf") else "", "pricinne" if rec.get("truth_causal") else "")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as h:
            json.dump({"nets": len(nets), "net_days": net_days, "cells": rows,
                       "refusals": {f"{e}|{r}": v for (e, r), v in refusals.items()},
                       "admitted_on_attack": attacks_admitted}, h, indent=1)


if __name__ == "__main__":
    main()
