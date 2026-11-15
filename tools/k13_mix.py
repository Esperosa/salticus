#!/usr/bin/env python3
"""Krok 13, dodatek A: vyhodnocení řízených mixů (`--mix on`).

Vstup: `--runs` adresáře běhů s `--mix on` (networks.jsonl, události mají `mix`:
incident, relation 0 společná příčina / 1 souběh / 2 následek, role, pair) a volitelně
`--dump` soubor(y) `K13_INC_DUMP` (události nálezů s label = index pravdy).
Výstup (předregistrace A1 až A5 v impl-krok13.md):
 A1 detekce složek mixu proti téže rodině mimo mix (v týchž během), po dvojicích a složkách
 A2 omylem zavřené složky
 A3 čistota seskupení v incidentech, které obsahují složku mixu, + úplnost
 A4 chybné spojení (souběh bez vazby ve stejném incidentu) a rozdělení (společná příčina rozdělená)
 A5 správná kategorie složky (provozní značka ops_shown/ops_annotated u poruch a změn, bez ní u útoků)
Seskupení: `base` = host nebo indikátor (1 h), `v2` = (host, protějšek) nebo (host, typ), 1 h.

Použití: python -I tools/k13_mix.py --families TSV --runs D1,D2 [--dump F1,F2] [--out F]
"""
import argparse
import collections
import itertools
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import wilson  # noqa: E402

REL = {0: "společná příčina", 1: "souběh bez vazby", 2: "následek"}
CATS = {"security": "útok", "ops_fault": "porucha", "benign_change": "neškodná změna"}


def load_runs(dirs):
    rows = {}
    for d in dirs:
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as h:
            for line in h:
                if line.strip():
                    r = json.loads(line)
                    rows[(r["run_seed"], r["network_id"])] = r
    return rows


def groups(events, mode, gap=3600):
    n = len(events)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def keys(e):
        if mode == "base":
            return ["h:" + e["host"]] + ["i:" + x for x in e["ind"]]
        ks = ["hk:%s|%s" % (e["host"], e["kind"])]
        ks += ["hp:%s|%s" % (e["host"], x) for x in e["ind"] if x != e["host"]]
        return ks

    last = {}
    for i in sorted(range(n), key=lambda i: events[i]["ts"]):
        for k in keys(events[i]):
            j = last.get(k)
            if j is not None and events[i]["ts"] - events[j]["ts"] <= gap:
                a, b = find(i), find(j)
                if a != b:
                    parent[a] = b
            last[k] = i
    g = collections.defaultdict(list)
    for i in range(n):
        g[find(i)].append(i)
    return list(g.values())


def ci(k, n):
    p, lo, hi = wilson(k, n)
    return f"{100 * p:.1f} ({100 * lo:.1f} až {100 * hi:.1f})".replace(".", ",")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--runs", required=True)
    ap.add_argument("--dump", default="")
    ap.add_argument("--out")
    args = ap.parse_args()
    cat = {}
    with open(args.families, encoding="utf-8") as h:
        next(h)
        for line in h:
            p = line.rstrip("\n").split("\t")
            cat[p[0]] = p[1]
    rows = load_runs(args.runs.split(","))
    solo = collections.defaultdict(lambda: [0, 0])
    comp = collections.defaultdict(lambda: [0, 0, 0, 0, 0, 0])  # n, det, wrong, cls_n, cls_ok, fam
    pair_comp = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
    mix_ids = {}
    for key, r in rows.items():
        for a in r.get("attacks", []):
            if not (a.get("emitted") and a.get("cf") is not None):
                continue
            fam = a["family"]
            m = a.get("mix")
            if m is None:
                solo[fam][0] += 1
                solo[fam][1] += int(bool(a["cf"]))
                continue
            mix_ids[(key, a["id"])] = m
            c = comp[(m["pair"], m["role"])]
            c[0] += 1
            c[1] += int(bool(a["cf"]))
            if (a.get("k7") or {}).get("wrong_closed", 0) > 0:
                c[2] += 1
            if a["cf"]:
                c[3] += 1
                ops = bool(a.get("ops_shown")) or bool((a.get("k7") or {}).get("ops_annotated"))
                want_ops = cat.get(fam) != "security"
                c[4] += int(ops == want_ops)
            pc = pair_comp[m["pair"]][m["role"]]
            pc[0] += 1
            pc[1] += int(bool(a["cf"]))
    pairs_def = None
    fams = {}
    for key, r in rows.items():
        for a in r.get("attacks", []):
            m = a.get("mix")
            if m:
                fams[(m["pair"], m["role"])] = a["family"]
    out = ["## Krok 13, dodatek A: řízené mixy", "",
           f"Sítí {len(rows)}, událostí v mixech {sum(c[0] for c in comp.values())}.", "",
           "### A1, A2, A5: složky po dvojicích", "",
           "| dvojice | vztah | složka | rodina | n | detekce (Wilson) | samostatně | rozdíl p. b. | omylem zavřené | kategorie správně |",
           "|---:|---|---|---|---:|---|---|---:|---:|---|"]
    rel_of = {}
    for key, r in rows.items():
        for a in r.get("attacks", []):
            m = a.get("mix")
            if m:
                rel_of[m["pair"]] = m["relation"]
    tot = [0, 0, 0, 0, 0, 0, 0]
    ratios = []
    for (pair, role) in sorted(comp):
        c = comp[(pair, role)]
        fam = fams.get((pair, role), "?")
        s = solo.get(fam, [0, 0])
        sp = s[1] / s[0] if s[0] else float("nan")
        dp = c[1] / c[0] if c[0] else float("nan")
        if s[0] >= 10 and c[0]:
            ratios.append(dp / sp if sp else float("nan"))
        out.append(f"| {pair} | {REL.get(rel_of.get(pair), '?')} | {role + 1} | {fam} ({CATS.get(cat.get(fam), '?')}) | {c[0]} | "
                   f"{ci(c[1], c[0])} | {100 * sp:.1f} (n {s[0]}) | {100 * (dp - sp):+.1f} | {c[2]} | "
                   f"{ci(c[4], c[3]) if c[3] else '-'} |".replace(".", ","))
        tot[0] += c[0]; tot[1] += c[1]; tot[2] += c[2]; tot[3] += c[3]; tot[4] += c[4]
    out += ["", f"Celkem složek {tot[0]}, zobrazeno {ci(tot[1], tot[0])}, omylem zavřeno {tot[2]}, "
                f"správná kategorie {ci(tot[4], tot[3]) if tot[3] else '-'} (A5; cíl 90 % ladicí, 85 % držené).", ""]
    # A1 po vztazích: relativní detekce
    by_rel = collections.defaultdict(lambda: [0, 0, 0.0])
    for (pair, role), c in comp.items():
        fam = fams.get((pair, role), "?")
        s = solo.get(fam, [0, 0])
        if s[0] >= 10:
            r_ = by_rel[rel_of.get(pair)]
            r_[0] += c[0]
            r_[1] += c[1]
            r_[2] += c[0] * (s[1] / s[0])
    out += ["### A1: detekce složek relativně k samostatné rodině (jen rodiny s n >= 10 mimo mix)", "",
            "| vztah | složek | detekce v mixu | očekáváno samostatně | relativně |", "|---|---:|---|---:|---:|"]
    for rel, v in sorted(by_rel.items(), key=lambda t: (t[0] is None, t[0])):
        exp = v[2] / v[0] if v[0] else float("nan")
        got = v[1] / v[0] if v[0] else float("nan")
        out.append(f"| {REL.get(rel, '?')} | {v[0]} | {ci(v[1], v[0])} | {100 * exp:.1f} | {got / exp if exp else float('nan'):.3f} |".replace(".", ","))
    out.append("")
    # A3 A4 ze seskupení
    if args.dump:
        for mode in ("base", "v2"):
            fin = pure = grouped_inc = merge_bad = merge_all = split = join_all = 0
            pair_pairs = pair_joined = 0
            for path in args.dump.split(","):
                with open(path, encoding="utf-8") as h:
                    for line in h:
                        if not line.strip():
                            continue
                        d = json.loads(line)
                        key = (d["seed"], d["net"])
                        ev = d["events"]
                        gs = groups(ev, mode)
                        member = {}
                        for gi, g in enumerate(gs):
                            for i in g:
                                member[i] = gi
                        # truth -> mix
                        lab_mix = {}
                        for i, e in enumerate(ev):
                            if e["label"] is not None and (key, e["label"]) in mix_ids:
                                lab_mix[e["label"]] = mix_ids[(key, e["label"])]
                        for g in gs:
                            if len(g) < 2:
                                continue
                            labs = [ev[i]["label"] for i in g]
                            if not any(l in lab_mix for l in labs if l is not None):
                                continue
                            c = collections.Counter(labs)
                            none = c.pop(None, 0)
                            best = max(max(c.values(), default=0), 1 if none else 0)
                            fin += len(g)
                            pure += best
                            grouped_inc += 1
                            incs = {(lab_mix[l]["incident"], lab_mix[l]["relation"]) for l in set(labs) if l in lab_mix}
                            # chybné spojení: ve skupině jsou obě složky souběhu bez vazby
                            for (inc, rel) in incs:
                                both = {lab_mix[l]["role"] for l in set(labs) if l in lab_mix and lab_mix[l]["incident"] == inc}
                                if rel == 1 and both == {0, 1}:
                                    merge_bad += 1
                            merge_all += 1
                        by_inc = collections.defaultdict(dict)
                        for l, m in lab_mix.items():
                            by_inc[m["incident"]][m["role"]] = (l, m["relation"])
                        for inc, roles in by_inc.items():
                            if len(roles) != 2:
                                continue
                            (la, rel), (lb, _) = roles[0], roles[1]
                            ia = [i for i, e in enumerate(ev) if e["label"] == la]
                            ib = [i for i, e in enumerate(ev) if e["label"] == lb]
                            if not ia or not ib:
                                continue
                            joined = any(member[x] == member[y] for x in ia for y in ib)
                            if rel in (0, 2):
                                join_all += 1
                                split += int(not joined)
                            else:
                                pair_pairs += 1
                                pair_joined += int(joined)
            out += [f"### A3 a A4 ({'původní seskupení (host nebo indikátor, 1 h)' if mode == 'base' else 'incident_v2 (host+protějšek nebo host+typ, 1 h)'})", "",
                    f"- skupin s nálezy z mixu a >= 2 nálezy: {grouped_inc}, nálezů v nich {fin}, čistota {100 * pure / max(fin, 1):.1f} %, nálezů na incident {fin / max(grouped_inc, 1):.2f}".replace(".", ","),
                    f"- chybné spojení: dvojice souběhu bez vazby spojené do jedné skupiny: {pair_joined} z {pair_pairs} dvojic s oběma složkami nalezenými ({100 * pair_joined / max(pair_pairs, 1):.1f} %; cíl <= 15 %)".replace(".", ","),
                    f"- společná příčina a následek rozdělené do různých skupin: {split} z {join_all} ({100 * split / max(join_all, 1):.1f} %; cíl <= 30 %)".replace(".", ","),
                    ""]
    text = "\n".join(out) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as h:
            h.write(text)
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
