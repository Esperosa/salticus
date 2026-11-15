#!/usr/bin/env python3
"""Protokol měření kroku 13/14: maticové párové srovnání ramen po sítích.

Vstup: `--base` a `--cand` = seznam adresářů běhů (soak run, `networks.jsonl`); páruje se
podle (run_seed, network_id), nepárové sítě se vynechají a spočtou. Konfigurace sítě
se odvozuje z archetypu: small = Soho/Smb/IotHeavy, medium = Enterprise/Campus/Hospital/
Industrial, large = Datacenter/Cloud/Metro (XXXL se hlásí zvlášť podle size_class).
Jednotka analýzy je síť. Intervaly: bootstrap po sítích stratifikovaný po seed x konfigurace
(B = 2000, pevný seed), párově (stejné vzorkování sítí pro obě ramena), poměr součtů.
Výstup: celkem, po konfiguracích, rozptyl mezi seedy, po rodinách (bezpečnostní a hn_*).

Pouziti: python -I tools/k13_matrix.py --families TSV --base D1,D2 --cand D3,D4 [--out F] [--title T]
"""
import argparse
import json
import os
import random
import sys
from collections import defaultdict

B = 2000
SMALL = {"Soho", "Smb", "IotHeavy"}
MEDIUM = {"Enterprise", "Campus", "Hospital", "Industrial"}
LARGE = {"Datacenter", "Cloud", "Metro"}


def config_of(row):
    a = row.get("archetype")
    if a in SMALL:
        return "small"
    if a in MEDIUM:
        return "medium"
    if a in LARGE:
        return "large"
    return "other"


def load(dirs):
    rows = {}
    for d in dirs:
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as h:
            for line in h:
                if line.strip():
                    r = json.loads(line)
                    rows[(r["run_seed"], r["network_id"])] = r
    return rows


def read_categories(path):
    cat = {}
    with open(path, encoding="utf-8") as h:
        next(h)
        for line in h:
            p = line.rstrip("\n").split("\t")
            cat[p[0]] = p[1]
    return cat


def net_stats(row, cat):
    """Po síti: součty pro metriky (čitatel, jmenovatel)."""
    s = defaultdict(float)
    s["fp"] = row["output"].get("displayed_fp", 0)
    s["days"] = row.get("virtual_days", 0) or 0
    fam = defaultdict(lambda: [0, 0])
    for a in row.get("attacks", []):
        if not (a.get("emitted") and a.get("cf") is not None):
            continue
        f = a["family"]
        fam[f][0] += 1
        fam[f][1] += int(bool(a["cf"]))
        s["att_n"] += 1
        if (a.get("k7") or {}).get("wrong_closed", 0) > 0:
            s["wrong"] += 1
        if cat.get(f) == "security":
            s["sec_n"] += 1
            s["sec_k"] += int(bool(a["cf"]))
        if f.startswith("hn_"):
            s["hn_n"] += 1
            s["hn_k"] += int(bool(a["cf"]))
    s["fam"] = dict(fam)
    return s


def ratio(items, num, den):
    n = sum(i[num] for i in items)
    d = sum(i[den] for i in items)
    return n / d if d else float("nan")


def fam_ratio(items, f):
    n = sum(i["fam"].get(f, [0, 0])[0] for i in items)
    k = sum(i["fam"].get(f, [0, 0])[1] for i in items)
    return (k / n if n else float("nan")), n


def boot(strata, stat, rng):
    """strata: dict stratum -> list of (a, b) párů statistik sítí; stat(listA, listB) -> hodnota."""
    out = []
    keys = sorted(strata)
    for _ in range(B):
        sa, sb = [], []
        for k in keys:
            items = strata[k]
            for _i in range(len(items)):
                a, b = items[rng.randrange(len(items))]
                sa.append(a)
                sb.append(b)
        out.append(stat(sa, sb))
    vals = sorted(v for v in out if v == v)
    if not vals:
        return (float("nan"), float("nan"))
    return vals[int(0.025 * len(vals))], vals[int(0.975 * len(vals)) - 1]


def fmt(x, pct=False, d=2):
    if x != x:
        return "-"
    return (f"{100 * x:.1f}" if pct else f"{x:.{d}f}").replace(".", ",")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--cand", required=True)
    ap.add_argument("--out")
    ap.add_argument("--title", default="Krok 13, maticové párové srovnání")
    ap.add_argument("--min-n", type=int, default=20)
    args = ap.parse_args()
    cat = read_categories(args.families)
    base = load(args.base.split(","))
    cand = load(args.cand.split(","))
    keys = sorted(set(base) & set(cand))
    unpaired = len(set(base) ^ set(cand))
    pairs = []
    for k in keys:
        pairs.append((k, config_of(base[k]), net_stats(base[k], cat), net_stats(cand[k], cat)))
    rng = random.Random(20261514)
    seeds = sorted({k[0] for k, *_ in pairs})
    cfgs = ["small", "medium", "large", "other"]
    cells = defaultdict(int)
    for k, c, *_ in pairs:
        cells[(k[0], c)] += 1
    out = [f"## {args.title}", "",
           f"Sítí v párech {len(pairs)} (nepárových {unpaired}), seedů {len(seeds)}, buněk seed x konfigurace "
           f"{len(cells)}. Intervaly 95 % bootstrapem po sítích stratifikovaným po seed x konfigurace (B = {B}), párově.", ""]

    def strata_of(sel):
        st = defaultdict(list)
        for k, c, a, b in sel:
            st[(k[0], c)].append((a, b))
        return st

    def metric_rows(sel, label):
        st = strata_of(sel)
        a_items = [a for *_, a, _b in sel]
        b_items = [b for *_, _a, b in sel]
        rows = []
        for name, num, den, pct in [("zobrazené FP na síť-den", "fp", "days", False),
                                    ("detekce bezpečnostních útoků", "sec_k", "sec_n", True),
                                    ("hn_* zobrazeno (FP z pohledu útoku)", "hn_k", "hn_n", True),
                                    ("útoky s omylem zavřeným", "wrong", "att_n", True)]:
            ra, rb = ratio(a_items, num, den), ratio(b_items, num, den)
            if name.startswith("zobrazené"):
                lo, hi = boot(st, lambda x, y: ratio(y, num, den) / max(ratio(x, num, den), 1e-12), rng)
                diff = f"poměr {fmt(rb / max(ra, 1e-12), d=3)} ({fmt(lo, d=3)} až {fmt(hi, d=3)})"
            else:
                lo, hi = boot(st, lambda x, y: ratio(y, num, den) - ratio(x, num, den), rng)
                diff = f"rozdíl {100 * (rb - ra):+.1f} ({100 * lo:+.1f} až {100 * hi:+.1f}) p. b.".replace(".", ",").replace("p, b,", "p. b.")
            rows.append(f"| {label} | {name} | {fmt(ra, pct)} | {fmt(rb, pct)} | {diff} |")
        return rows

    out += ["### Celkem a po konfiguracích", "", "| skupina (sítí) | ukazatel | základ | kandidát | rozdíl |", "|---|---|---:|---:|---|"]
    out += metric_rows(pairs, f"vše ({len(pairs)})")
    for c in cfgs:
        sel = [p for p in pairs if p[1] == c]
        if sel:
            out += metric_rows(sel, f"{c} ({len(sel)})")
    xl = [p for p in pairs if (base[p[0]].get("size_class") or "").startswith(("XXL", "XXXL"))]
    if xl:
        out += metric_rows(xl, f"XXL a větší ({len(xl)})")
    out += ["", "### Rozptyl mezi seedy (detekce bezpečnostních útoků a FP na síť-den, kandidát minus základ)", "",
            "| seed | sítí | detekce základ | detekce kandidát | FP základ | FP kandidát |", "|---|---:|---:|---:|---:|---:|"]
    diffs = []
    for s in seeds:
        sel = [p for p in pairs if p[0][0] == s]
        a_items = [p[2] for p in sel]
        b_items = [p[3] for p in sel]
        da, db = ratio(a_items, "sec_k", "sec_n"), ratio(b_items, "sec_k", "sec_n")
        diffs.append(db - da)
        out.append(f"| {s} | {len(sel)} | {fmt(da, True)} | {fmt(db, True)} | "
                   f"{fmt(ratio(a_items, 'fp', 'days'))} | {fmt(ratio(b_items, 'fp', 'days'))} |")
    if diffs:
        out += ["", f"Rozdíl detekce po seedech: min {100 * min(diffs):+.1f}, max {100 * max(diffs):+.1f} p. b. ".replace(".", ",").replace("p, b,", "p. b.") + ""
                    f"(seedů se zlepšením {sum(d > 0 for d in diffs)} z {len(diffs)})."]
    out += ["", "### Rodiny (n = útoků s toky v obou ramenech)", "",
            "| rodina | kategorie | n | základ | kandidát | rozdíl p. b. (95 %) |", "|---|---|---:|---:|---:|---|"]
    st_all = strata_of(pairs)
    fams = sorted({f for *_, a, _ in pairs for f in a["fam"]} | {f for *_, b in pairs for f in b["fam"]})
    for f in fams:
        a_items = [p[2] for p in pairs]
        b_items = [p[3] for p in pairs]
        ra, n = fam_ratio(a_items, f)
        rb, _ = fam_ratio(b_items, f)
        if n < args.min_n or ra != ra:
            continue
        lo, hi = boot(st_all, lambda x, y, f=f: fam_ratio(y, f)[0] - fam_ratio(x, f)[0], rng)
        out.append(f"| {f} | {cat.get(f, '?')} | {n} | {fmt(ra, True)} | {fmt(rb, True)} | "
                   f"{100 * (rb - ra):+.1f} ({100 * lo:+.1f} až {100 * hi:+.1f}) |".replace(".", ","))
    text = "\n".join(out) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as h:
            h.write(text)
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
