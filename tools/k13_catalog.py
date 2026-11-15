#!/usr/bin/env python3
"""Krok 13, dodatek B: měření klasifikace podle katalogu (B2, B3, B6).

Vstup: adresáře běhů (`networks.jsonl`, útoky nesou `catalog`: `třída|catalog_id` -> počet zobrazených
nálezů) a katalog `data/incident-catalog.json`. Očekávaná třída: bezpečnostní rodina = `utok`,
porucha = `porucha`, neškodná změna = `zmena`; nejednoznačné typy katalogu (`nejednoznacne`) se
generují s příčinou poruchy a hlásí se zvlášť. Očekávaný `catalog_id` = typ katalogu s `sim_variant`
rovným štítku rodiny. Jednotka: zobrazený nález pripsaný pravdě; po rodinách a celkem.

B2: správná třída >= 90 % (ladicí) / 85 % (držené), po typech.
B3: útok zařazený jako porucha/změna <= 10 %; porucha/změna zařazená jako útok <= 10 %.
B6: správný catalog_id >= 80 % u typů s generátorem.

Použití: python -I tools/k13_catalog.py --families TSV --catalog JSON --runs D1,D2 [--out F]
"""
import argparse
import collections
import json
import os


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--catalog", required=True)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--out")
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
    tab = collections.defaultdict(lambda: collections.Counter())
    for d in a.runs.split(","):
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as h:
            for line in h:
                if not line.strip():
                    continue
                r = json.loads(line)
                for at in r.get("attacks", []):
                    fam = at["family"]
                    c = at.get("catalog") or {}
                    if fam in exp:
                        want_cls, want_id = exp[fam]
                    elif cat.get(fam) == "security":
                        want_cls, want_id = "utok", None
                    else:
                        continue
                    for key, n in c.items():
                        cls, cid = key.split("|")
                        t = tab[fam]
                        t["n"] += n
                        t["cls_ok"] += n if (cls == want_cls or (want_cls == "nejednoznacne" and cls != "utok")) else 0
                        t["as_attack"] += n if cls == "utok" else 0
                        t["as_ops"] += n if cls != "utok" else 0
                        t["id_ok"] += n if (want_id and cid == want_id) else 0
    lines = ["## Krok 13, dodatek B: klasifikace podle katalogu (B2, B3, B6)", ""]
    lines.append("| rodina | očekávaná třída | nálezů | třída správně % | jako útok % | jako provoz % | catalog_id správně % |")
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    groups = {"utok": collections.Counter(), "porucha": collections.Counter(), "zmena": collections.Counter(), "nejednoznacne": collections.Counter()}
    ids = collections.Counter()
    for fam in sorted(tab):
        t = tab[fam]
        n = t["n"]
        if n == 0:
            continue
        w = exp[fam][0] if fam in exp else "utok"
        pct = lambda x: f"{100 * x / n:.1f}"
        lines.append(
            f"| {fam} | {w} | {n} | {pct(t['cls_ok'])} | {pct(t['as_attack'])} | {pct(t['as_ops'])} | "
            f"{pct(t['id_ok']) if fam in exp else '-'} |"
        )
        g = groups[w]
        for k in ("n", "cls_ok", "as_attack", "as_ops"):
            g[k] += t[k]
        if fam in exp:
            ids["n"] += n
            ids["ok"] += t["id_ok"]
    lines += ["", "| očekávaná třída | nálezů | třída správně % | zařazeno jako útok % | zařazeno jako provoz % |", "|---|---:|---:|---:|---:|"]
    for w, g in groups.items():
        if g["n"]:
            lines.append(f"| {w} | {g['n']} | {100*g['cls_ok']/g['n']:.1f} | {100*g['as_attack']/g['n']:.1f} | {100*g['as_ops']/g['n']:.1f} |")
    if ids["n"]:
        lines.append("")
        lines.append(f"B6: správný catalog_id u typů s generátorem {100*ids['ok']/ids['n']:.1f} % z {ids['n']} nálezů (cíl >= 80 %).")
    out = "\n".join(lines) + "\n"
    if a.out:
        open(a.out, "w", encoding="utf-8").write(out)
    print(out)


if __name__ == "__main__":
    main()
