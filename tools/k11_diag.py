#!/usr/bin/env python3
"""Diagnostika kroku 11: zmeskane utoky po rodinach do skupin a/b/c a rozbor variant.

a = engine nevydal zadny nalez (neni detected), b = nalez vznikl, ale nebyl zobrazen nebo byl zavren/utisen,
c = nalez zobrazen, ale kontrafaktual ho nepripisuje utoku, nebo ma jiny typ nez hodnoceni ceka.
Pouziti: python tools/k11_diag.py --families TSV --arm DIR [DIR ...] [--fam a,b] [--vars] [--out FILE]
"""
import argparse
import sys
import os
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import attacks, load, wilson  # noqa: E402
from soak_k9 import read_families, pc  # noqa: E402


def group(a, info):
    if a["cf"]:
        if info["types"] & set(a.get("cf_types", [])) or not info["types"]:
            return "ok"
        return "c_typ"
    if not a["detected"]:
        return "a"
    k7 = a.get("k7") or {}
    if a.get("auto_closed") or k7.get("silenced"):
        return "b_zavreno"
    if not a["displayed"]:
        return "b_nezobrazeno"
    return "c_neprip"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--arm", nargs="+", required=True)
    ap.add_argument("--fam")
    ap.add_argument("--vars", action="store_true")
    ap.add_argument("--flows", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    table = read_families(args.families)
    rows = load(args.arm)
    fams = defaultdict(list)
    for _, a in attacks(rows):
        fams[a["family"]].append(a)
    want = set(args.fam.split(",")) if args.fam else None
    out = []
    order = sorted((f for f in fams if table.get(f, {"category": "security"})["category"] == "security"),
                   key=lambda f: -sum(1 for a in fams[f] if not a["cf"]))
    out.append("| rodina | n | detekce % | miss | a | b_zavreno | b_nezobrazeno | c_neprip | c_typ |")
    out.append("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for f in order:
        if want and f not in want:
            continue
        info = table.get(f, {"types": set(), "category": "security"})
        g = Counter(group(a, info) for a in fams[f])
        n = len(fams[f])
        miss = n - sum(1 for a in fams[f] if a["cf"])
        out.append(f"| {f} | {n} | {pc(1 - miss / n)} | {miss} | {g['a']} | {g['b_zavreno']} | {g['b_nezobrazeno']} | {g['c_neprip']} | {g['c_typ']} |")
        if args.vars and want:
            for dim in ("tempo", "jitter", "sources", "duration", "volume", "off_hours", "blend"):
                cnt = defaultdict(lambda: [0, 0])
                for a in fams[f]:
                    v = (a.get("variation") or {}).get(dim)
                    cnt[v][0] += 1
                    cnt[v][1] += int(bool(a["cf"]))
                out.append(f"    {f} {dim}: " + ", ".join(f"{k}: {v[1]}/{v[0]}" for k, v in sorted(cnt.items(), key=lambda x: str(x[0]))))
            for key in ("ids_visible",):
                cnt = defaultdict(lambda: [0, 0])
                for a in fams[f]:
                    cnt[a.get(key)][0] += 1
                    cnt[a.get(key)][1] += int(bool(a["cf"]))
                out.append(f"    {f} {key}: " + ", ".join(f"{k}: {v[1]}/{v[0]}" for k, v in cnt.items()))
            cnt = defaultdict(lambda: [0, 0])
            for a in fams[f]:
                b = round(a["intensity"] * 4) / 4
                cnt[b][0] += 1
                cnt[b][1] += int(bool(a["cf"]))
            out.append(f"    {f} intensity: " + ", ".join(f"{k}: {v[1]}/{v[0]}" for k, v in sorted(cnt.items())))
            cnt = defaultdict(lambda: [0, 0])
            for a in fams[f]:
                cnt[a["cycles"]][0] += 1
                cnt[a["cycles"]][1] += int(bool(a["cf"]))
            out.append(f"    {f} cycles: " + ", ".join(f"{k}: {v[1]}/{v[0]}" for k, v in sorted(cnt.items())))
            cnt = defaultdict(lambda: [0, 0])
            for a in fams[f]:
                cnt[bool(a["overlaps"])][0] += 1
                cnt[bool(a["overlaps"])][1] += int(bool(a["cf"]))
            out.append(f"    {f} prekryv_s_neskodnou_udalosti: " + ", ".join(f"{k}: {v[1]}/{v[0]}" for k, v in cnt.items()))
    text = "\n".join(out)
    if args.flows and want:
        text += "\n\n" + flows_report(rows, table, sorted(want))
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    else:
        print(text)



def flows_report(rows, table, fams_wanted):
    """Souhrn toku (diag) po skupinach pro vybrane rodiny: medianove flows, zdroje, cile, porty, bajty."""
    from statistics import median
    out = []
    by = defaultdict(list)
    for _, a in attacks(rows):
        if a["family"] in fams_wanted:
            by[a["family"]].append(a)
    for f in fams_wanted:
        items = by.get(f, [])
        info = table.get(f, {"types": set(), "category": "security"})
        out.append(f"### {f} (n={len(items)})")
        out.append("| skupina | n | flows med/min/max | max_cycle_flows med | src med | dst med | porty med | failed med | bajty med | senzor ztracen (>0) | videno med | videno=0 | ids |")
        out.append("|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        groups = defaultdict(list)
        for a in items:
            groups[group(a, info)].append(a)
        for g in sorted(groups):
            xs = [a for a in groups[g] if a.get("diag")]
            if not xs:
                continue
            m = lambda k: median([a["diag"][k] for a in xs])
            fl = [a["diag"]["flows"] for a in xs]
            lost = sum(1 for a in xs if a["diag"]["sensor_lost_cycles"] > 0)
            ids = sum(1 for a in xs if a.get("ids_visible"))
            out.append(f"| {g} | {len(xs)} | {median(fl)}/{min(fl)}/{max(fl)} | {m('max_cycle_flows')} | {m('src_n')} | {m('dst_n')} | {m('port_n')} | {m('failed')} | {m('bytes')} | {lost} | {m('visible_flows')} | {sum(1 for a in xs if a['diag'].get('visible_flows',0)==0)} | {ids} |")
        out.append("")
    return "\n".join(out)


if __name__ == "__main__":
    main()
