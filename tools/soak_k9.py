#!/usr/bin/env python3
"""Vyhodnoceni kroku 9 (docs/diplomka/eval/impl-krok9.md, sekce B).

Vstup: `--arm NAZEV DIR [DIR ...]` (prvni rameno je zaklad srovnani) a `--families TSV`
(vystup `salticus-program soak families`). Pro kazdou rodinu a variantu vypise n,
detekci (zobrazena, kontrafaktualni) a spravny typ s Wilsonovym intervalem, kategorii,
ATT&CK, stav proti prahu K9-1/K9-2/K9-8, u provoznich poruch dale klasifikaci
(zobrazeno ve fronte provoz), seskupeni (nalezy na incident) a latenci.
Jen standardni knihovna Pythonu 3.
"""
import argparse
import csv
import os
import sys
from collections import defaultdict
from statistics import median

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import attacks, load, wilson  # noqa: E402

MIN_N = 50
DET_MIN, DET_LO = 0.90, 0.85
TYPE_MIN, TYPE_LO = 0.85, 0.80


def read_families(path):
    table = {}
    with open(path, encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            row["types"] = set(filter(None, row["expected_types"].split(",")))
            table[row["label"]] = row
    return table


def pc(x):
    return "-" if x != x else f"{100 * x:.1f}".replace(".", ",")


def ci(k, n):
    p, lo, hi = wilson(k, n)
    return f"{pc(p)} ({pc(lo)} až {pc(hi)})"


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def per_family(rows, table):
    groups = defaultdict(list)
    for _, a in attacks(rows):
        groups[a["family"]].append(a)
    result = {}
    for label, items in groups.items():
        info = table.get(label, {"types": set(), "category": "security", "attack": "", "pattern": ""})
        n = len(items)
        hit = sum(1 for a in items if a["cf"])
        typed = sum(1 for a in items if a["cf"] and info["types"] & set(a.get("cf_types", [])))
        ops_shown = sum(1 for a in items if a.get("ops_shown"))
        findings = [a["k7"]["findings"] for a in items if a.get("k7") and a["k7"].get("findings")]
        latency = [a["k7"]["latency"] for a in items if a.get("k7") and a["k7"].get("latency") is not None]
        wrong = sum(1 for a in items if (a.get("k7") or {}).get("wrong_closed", 0) > 0)
        result[label] = dict(n=n, hit=hit, typed=typed, ops_shown=ops_shown, findings=findings,
                             latency=latency, wrong=wrong, info=info)
    return result


def status(r):
    if r["n"] < MIN_N:
        return "nedostatek dat"
    p, lo, _ = wilson(r["hit"], r["n"])
    ok = p >= DET_MIN and lo >= DET_LO
    pt, lot, _ = wilson(r["typed"], r["n"])
    tok = pt >= TYPE_MIN and lot >= TYPE_LO
    if ok and tok:
        return "splněno"
    if ok:
        return "detekce ano, typ ne"
    return "pod prahem"


def render(name, rows, table):
    fam = per_family(rows, table)
    out = [f"### Rameno `{name}` ({len(rows)} sítí, {sum(r['n'] for r in fam.values())} útoků a poruch s toky)", ""]
    out += ["| rodina | kategorie | ATT&CK | n | detekce % (Wilson) | správný typ % (Wilson) | zavřeno omylem | stav |",
            "|---|---|---|---:|---|---|---:|---|"]
    for label in sorted(fam, key=lambda k: (fam[k]["info"]["category"], k)):
        r = fam[label]
        out.append(f"| {label} | {r['info']['category']} | {r['info']['attack'] or '-'} | {r['n']} | "
                   f"{ci(r['hit'], r['n'])} | {ci(r['typed'], r['n'])} | {r['wrong']} | {status(r)} |")
    out.append("")
    # souhrn po kategoriich a po vzorech (vetsi n nez po jednotlivych variantach)
    for title, keyf in (("kategorie", lambda r: r["info"]["category"]),
                        ("vzor chování", lambda r: r["info"].get("pattern") or "base")):
        agg = defaultdict(lambda: dict(n=0, hit=0, typed=0, ops=0, findings=[], latency=[]))
        for r in fam.values():
            a = agg[keyf(r)]
            a["n"] += r["n"]
            a["hit"] += r["hit"]
            a["typed"] += r["typed"]
            a["ops"] += r["ops_shown"]
            a["findings"] += r["findings"]
            a["latency"] += r["latency"]
        out += [f"Souhrn podle: {title}", "",
                "| skupina | n | detekce % (Wilson) | správný typ % | fronta provoz % | medián nálezů na incident | latence medián / p90 (cykly) |",
                "|---|---:|---|---|---:|---:|---|"]
        for key in sorted(agg):
            a = agg[key]
            med = median(a["findings"]) if a["findings"] else float("nan")
            lat = f"{median(a['latency'])} / {percentile(a['latency'], 0.9)}" if a["latency"] else "-"
            ops = pc(a["ops"] / a["n"]) if a["n"] else "-"
            out.append(f"| {key} | {a['n']} | {ci(a['hit'], a['n'])} | {ci(a['typed'], a['n'])} | {ops} | "
                       f"{'-' if med != med else med} | {lat} |")
        out.append("")
    return "\n".join(out), fam


def totals(rows):
    items = attacks(rows)
    days = sum(r.get("virtual_days", 0) for r in rows.values())
    fp = sum(r["output"].get("displayed_fp_suspect", r["output"].get("displayed_fp", 0)) for r in rows.values())
    shown = sum(r["output"].get("displayed", 0) for r in rows.values())
    wrong = sum(1 for _, a in items if (a.get("k7") or {}).get("wrong_closed", 0) > 0)
    return dict(n=len(items), hit=sum(1 for _, a in items if a["cf"]), days=days, fp=fp, shown=shown,
                wrong=wrong, nets=len(rows))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", nargs="+", action="append", required=True)
    ap.add_argument("--families", required=True)
    ap.add_argument("--title", default="Krok 9")
    ap.add_argument("--out")
    args = ap.parse_args()
    table = read_families(args.families)
    arms = {spec[0]: load(spec[1:]) for spec in args.arm}
    lines = [f"## {args.title}", "", "### Souhrn ramen", "",
             "| rameno | sítí | útoků | detekce % (Wilson) | FP/síť-den | zobrazeno/síť-den | útoky s omylem zavřeným nálezem |",
             "|---|---:|---:|---|---:|---:|---|"]
    for name, rows in arms.items():
        t = totals(rows)
        days = max(t["days"], 1e-9)
        lines.append(f"| {name} | {t['nets']} | {t['n']} | {ci(t['hit'], t['n'])} | {t['fp'] / days:.2f} | "
                     f"{t['shown'] / days:.2f} | {t['wrong']} ({pc(t['wrong'] / max(t['n'], 1))} %) |")
    lines.append("")
    for name, rows in arms.items():
        text, _ = render(name, rows, table)
        lines += [text, ""]
    body = "\n".join(lines)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(body + "\n")
    else:
        print(body)


if __name__ == "__main__":
    main()
