#!/usr/bin/env python3
"""Krok 11: srovnani zakladu a kandidata po rodinach (opravene rodiny, neskodne hn_*, prenos na ostatni).

Pouziti: python tools/k11_cmp.py --families TSV --base DIR[,DIR] --cand DIR[,DIR] [--out FILE]
"""
import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import attacks, load, wilson  # noqa: E402
from soak_k9 import read_families, pc, totals  # noqa: E402

TARGET = ["drive_by_bulk_download", "bucket_mass_download", "exfil_alt_protocol_ftp",
          "cloud_api_discovery_burst", "clicks_to_rare_destination", "port_scan_horizontal"]
BIG = ["c2_beacon", "port_scan_horizontal", "port_scan_vertical", "exploit_attempt", "exfiltration",
       "credential_stuffing", "cryptomining"]


def fam_counts(rows):
    d = defaultdict(lambda: [0, 0])
    for _, a in attacks(rows):
        d[a["family"]][0] += 1
        d[a["family"]][1] += int(bool(a["cf"]))
    return d


def ci(k, n):
    p, lo, hi = wilson(k, n)
    return f"{pc(p)} ({pc(lo)} až {pc(hi)})"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--cand", required=True)
    ap.add_argument("--out")
    ap.add_argument("--title", default="Krok 11")
    args = ap.parse_args()
    table = read_families(args.families)
    base = load(args.base.split(","))
    cand = load(args.cand.split(","))
    fb, fc = fam_counts(base), fam_counts(cand)
    out = [f"## {args.title}", ""]
    tb, tc = totals(base), totals(cand)
    out += ["| ukazatel | základ | kandidát |", "|---|---|---|",
            f"| sítí | {tb['nets']} | {tc['nets']} |",
            f"| zobrazené FP na síť-den | {tb['fp'] / max(tb['days'], 1e-9):.2f} | {tc['fp'] / max(tc['days'], 1e-9):.2f} (poměr {(tc['fp'] / max(tc['days'], 1e-9)) / max(tb['fp'] / max(tb['days'], 1e-9), 1e-9):.3f}) |",
            f"| útoky s omylem zavřeným nálezem | {tb['wrong']} ({pc(tb['wrong'] / max(tb['n'], 1))} %) | {tc['wrong']} ({pc(tc['wrong'] / max(tc['n'], 1))} %) |"]
    sec = [f for f in fb if table.get(f, {}).get("category") == "security"]
    nb = sum(fb[f][0] for f in sec); kb_ = sum(fb[f][1] for f in sec)
    nc = sum(fc[f][0] for f in sec); kc = sum(fc[f][1] for f in sec)
    out += [f"| detekce bezpečnostních útoků (bez poruch a hn_*) | {ci(kb_, nb)} | {ci(kc, nc)} |", ""]

    def section(title, fams):
        out.extend([f"### {title}", "", "| rodina | n | detekce základ | detekce kandidát | rozdíl p. b. |", "|---|---:|---|---|---:|"])
        for f in fams:
            if f not in fb:
                continue
            n, kb1 = fb[f]
            kc1 = fc[f][1] if f in fc else 0
            n2 = fc[f][0] if f in fc else 0
            out.append(f"| {f} | {n}/{n2} | {ci(kb1, n)} | {ci(kc1, n2)} | {100 * (kc1 / max(n2, 1) - kb1 / max(n, 1)):+.1f} |".replace(".", ","))
        out.append("")

    section("Opravené rodiny", TARGET)
    section("Velké rodiny (kontrola, že se nezhoršily)", BIG)
    hn = sorted(f for f in fb if f.startswith("hn_"))
    section("Neškodné změny hn_* (podíl zobrazených = FP z pohledu útoku)", hn)
    other = [f for f in sorted(fb) if table.get(f, {}).get("category") == "security" and f not in TARGET and f not in BIG]
    chg = []
    for f in other:
        n, kb1 = fb[f]
        kc1 = fc[f][1] if f in fc else 0
        chg.append((kc1 / max(fc[f][0], 1) - kb1 / max(n, 1), f))
    chg.sort(reverse=True)
    out += ["### Přenos na ostatní bezpečnostní rodiny (největší změny, LOFO)", "", "| rodina | n | základ | kandidát | rozdíl p. b. |", "|---|---:|---|---|---:|"]
    for d, f in chg[:8] + [c for c in chg[-5:] if c[0] < 0]:
        n, kb1 = fb[f]
        kc1 = fc[f][1]
        out.append(f"| {f} | {n} | {ci(kb1, n)} | {ci(kc1, fc[f][0])} | {100 * d:+.1f} |".replace(".", ","))
    oth_b = sum(fb[f][1] for f in other); oth_n = sum(fb[f][0] for f in other)
    oth_c = sum(fc[f][1] for f in other); oth_nc = sum(fc[f][0] for f in other)
    out += ["", f"Všechny ostatní bezpečnostní rodiny dohromady: základ {ci(oth_b, oth_n)}, kandidát {ci(oth_c, oth_nc)}.", ""]
    text = "\n".join(out)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
