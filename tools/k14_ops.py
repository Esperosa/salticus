#!/usr/bin/env python3
"""Krok 14, část C2: vyhodnocení klasifikace poruch podle provozní telemetrie (C1 až C5, C10).

Vstup: adresáře běhů (`networks.jsonl`; útok nese `catalog`: `třída|catalog_id` -> počet zobrazených
nálezů a `ops_signals` = kolik provozních signálů událost doručila), `--families` (TSV rodina,
kategorie) a katalog. Jednotky: zobrazený nález (poměr součtů přes sítě) a událost (rozhodnuto
nejčastější třídou jejích nálezů). Intervaly Wilson 95 %.

Použití: python -I tools/k14_ops.py --families TSV --catalog JSON --runs D1,D2 [--out F]
"""
import argparse
import collections
import json
import math
import os


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 2
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - r, c + r


def pct(k, n):
    if n == 0:
        return "-"
    lo, hi = wilson(k, n)
    return f"{100*k/n:.1f} ({100*lo:.1f} až {100*hi:.1f}) n={n}".replace(".", ",")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out")
    ap.add_argument("--field", default="catalog")
    a = ap.parse_args()
    cat = {}
    with open(a.families, encoding="utf-8") as h:
        next(h)
        for line in h:
            p = line.rstrip("\n").split("\t")
            cat[p[0]] = p[1]
    cj = json.load(open(a.catalog, encoding="utf-8"))
    exp = {}
    for e in cj["incidents"]:
        v = e.get("sim_variant")
        if v:
            cls = {"porucha": "porucha", "neskodna_zmena": "zmena", "nejednoznacne": "nejednoznacne"}[e["category"]]
            exp[v] = (cls, e["id"])
    fault = collections.defaultdict(collections.Counter)  # rodina -> počty
    # souhrny: [k, n]
    c1 = [0, 0]
    c2_tel = [0, 0]
    c2_all = [0, 0]
    c3 = collections.Counter()  # nálezy bez doručené telemetrie
    c4 = collections.Counter()  # útoky: třída nálezů
    c4_ev = [0, 0]
    c5 = [0, 0]
    chg = [0, 0]
    unk = collections.Counter()
    wrong_fault = [0, 0]  # zavřené omylem poruchy (C6)
    by_type = collections.defaultdict(lambda: collections.Counter())
    for d in a.runs.split(","):
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as h:
            for line in h:
                if not line.strip():
                    continue
                r = json.loads(line)
                for at in r.get("attacks", []):
                    fam = at["family"]
                    cm = at.get(a.field) or {}
                    sig = at.get("ops_signals", 0)
                    is_sec = cat.get(fam) == "security"
                    if fam in exp:
                        want, wid = exp[fam]
                    elif is_sec:
                        want, wid = "utok", None
                    else:
                        continue
                    classes = collections.Counter()
                    for key, n in cm.items():
                        cls, cid = key.split("|")
                        classes[cls] += n
                        if want in ("porucha", "zmena", "nejednoznacne"):
                            t = by_type[fam]
                            t["n"] += n
                            t["cls_ok"] += n if cls == want else 0
                            t["id_ok"] += n if cid == wid else 0
                            t["neurceno"] += n if cls == "neurceno" else 0
                            t["sig"] += n if sig > 0 else 0
                    ntot = sum(classes.values())
                    if ntot == 0:
                        continue
                    if want == "porucha":
                        c1[0] += classes["porucha"]
                        c1[1] += ntot
                        if sig > 0:
                            c2_tel[1] += ntot
                            c2_tel[0] += sum(n for k, n in cm.items() if k.split("|")[1] == wid)
                            unk["tel_n"] += ntot
                            unk["tel_neurceno"] += classes["neurceno"]
                        else:
                            c3["n"] += ntot
                            c3["neurceno"] += classes["neurceno"]
                            c3["confident_wrong"] += classes["porucha"] + classes["zmena"]
                            c3["utok"] += classes["utok"]
                        c2_all[1] += ntot
                        c2_all[0] += sum(n for k, n in cm.items() if k.split("|")[1] == wid)
                        c5[0] += classes["utok"]
                        c5[1] += ntot
                    elif want in ("zmena", "nejednoznacne"):
                        chg[0] += classes[want]
                        chg[1] += ntot
                    elif is_sec:
                        c4["n"] += ntot
                        c4["as_fault"] += classes["porucha"] + classes["zmena"] + classes["nejednoznacne"]
                        c4["neurceno"] += classes["neurceno"]
                        c4_ev[1] += 1
                        c4_ev[0] += int((classes["porucha"] + classes["zmena"]) * 2 > ntot)
    lines = ["## Krok 14, část C2: klasifikace podle provozní telemetrie", ""]
    lines.append(f"- C1 správná třída `porucha` u nálezů z poruch: {pct(*c1)} (cíl >= 85 %)")
    lines.append(f"- C2 správné `catalog_id`, telemetrie doručena: {pct(*c2_tel)} (cíl >= 80 %); všechny nálezy poruch: {pct(*c2_all)}")
    n = c3["n"]
    lines.append(
        f"- C3 nálezy poruch bez doručené telemetrie: {n}; hlášeno „nelze určit“ {pct(c3['neurceno'], n)} (cíl >= 90 %), "
        f"jistě zařazeno jako porucha nebo změna {pct(c3['confident_wrong'], n)} (cíl <= 10 %), zůstalo útokem {pct(c3['utok'], n)}"
    )
    lines.append(f"- C4 útok maskovaný jako porucha: nálezů zařazených jako porucha, změna nebo nejednoznačné {pct(c4['as_fault'], c4['n'])} (cíl <= 5 %); událostí s většinou nálezů jako porucha nebo změna {pct(*c4_ev)}")
    lines.append(f"- C5 porucha maskovaná jako útok: nálezů z poruch zařazených jako útok {pct(*c5)} (cíl <= 10 %)")
    lines.append(f"- neškodné změny a nejednoznačné: správná třída {pct(*chg)}")
    lines.append(f"- C10 typ mimo katalog nebo tiché poruchy s doručenou telemetrií: hlášeno „nelze určit“ {pct(unk['tel_neurceno'], unk['tel_n'])} (smysl jen v rameni `--ops-unknown`)")
    lines += ["", "| typ | třída | nálezů | třída správně % | catalog_id správně % | nelze určit % | s telemetrií % |", "|---|---|---:|---:|---:|---:|---:|"]
    for fam in sorted(by_type):
        t = by_type[fam]
        n = t["n"]
        if n:
            f = lambda x: f"{100*x/n:.1f}".replace(".", ",")
            lines.append(f"| {fam} | {exp[fam][0]} | {n} | {f(t['cls_ok'])} | {f(t['id_ok'])} | {f(t['neurceno'])} | {f(t['sig'])} |")
    out = "\n".join(lines) + "\n"
    if a.out:
        open(a.out, "w", encoding="utf-8").write(out)
    print(out)


main()
