#!/usr/bin/env python3
"""Krok 14, část A: párové srovnání ramen endpointu (A1 až A12) nad k13_matrix.

Vstup: `--base` a `--cand` (seznamy adresářů běhů), `--families` TSV. Párování po sítích
(run_seed, network_id), bootstrap po sítích stratifikovaný po seed x konfigurace (B = 2000).
Výstup: A1 (rodiny, kde síť nestačí: souhrn a po rodinách), A2 (detekce celkem), A3 (FP poměr),
A4 (omylem zavřené s Wilsonovou horní mezí), A5 (hn_* zobrazeno), A9 (objem dat na host a den),
A10 podklad (detekce), doplněk: čas k rozhodnutí.

Použití: python -I tools/k14_endpoint.py --families TSV --base D1,D2 --cand D3,D4 [--out F] [--title T]
"""
import argparse
import math
import os
import random
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k13_matrix as km  # noqa: E402

NI = [
    "exfil_cloud_storage_upload",
    "bucket_mass_download",
    "clicks_to_rare_destination",
    "cloud_api_discovery_burst",
    "drive_by_bulk_download",
    "c2_cloud_storage_dead_drop",
    "dns_zone_enum_burst",
    "c2_dns_txt_beacon",
]


def wilson_hi(k, n, z=1.96):
    if n == 0:
        return float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    r = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c + r


def extra_stats(row):
    """Doplňkové součty po síti: objem endpointových dat, latence rozhodnutí."""
    o = row.get("output", {})
    k7 = (o.get("k7") or {})
    return {
        "ep_events": k7.get("endpoint_events_total", 0),
        "ep_bytes": k7.get("endpoint_bytes_total", 0),
        "ep_hosts": row.get("devices", 0) or 0,
        "refuted": o.get("ladder_refuted", 0),
        "refuted_wrong": o.get("ladder_refuted_wrong_cf", 0),
        "closures": o.get("auto_closures", 0),
        "closures_wrong": o.get("auto_closures_wrong_cf", 0),
        "lat_sum": o.get("ladder_latency_sum", 0),
        "lat_n": o.get("ladder_cases", 0),
        "shown": o.get("displayed", 0),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--families", required=True)
    ap.add_argument("--base", required=True)
    ap.add_argument("--cand", required=True)
    ap.add_argument("--out")
    ap.add_argument("--title", default="Krok 14, část A: endpoint")
    a = ap.parse_args()
    cat = km.read_categories(a.families)
    base = km.load(a.base.split(","))
    cand = km.load(a.cand.split(","))
    keys = sorted(set(base) & set(cand))
    unpaired = len(set(base) ^ set(cand))
    pairs = []
    for k in keys:
        pairs.append((k, km.config_of(base[k]), km.net_stats(base[k], cat), km.net_stats(cand[k], cat), extra_stats(base[k]), extra_stats(cand[k])))
    rng = random.Random(20261514)

    def strata(sel):
        st = defaultdict(list)
        for k, c, sa, sb, ea, eb in sel:
            st[(k[0], c)].append((sa, sb))
        return st

    def fam_sum(items, fams):
        n = sum(i["fam"].get(f, [0, 0])[0] for i in items for f in fams)
        k = sum(i["fam"].get(f, [0, 0])[1] for i in items for f in fams)
        return (k / n if n else float("nan")), n

    out = [f"## {a.title}", "", f"Sítí v párech {len(pairs)} (nepárových {unpaired}). Bootstrap po sítích stratifikovaný po seed x konfigurace, B = {km.B}.", ""]
    sa = [p[2] for p in pairs]
    sb = [p[3] for p in pairs]
    st = strata(pairs)

    def dr(num, den):
        ra, rb = km.ratio(sa, num, den), km.ratio(sb, num, den)
        lo, hi = km.boot(st, lambda x, y: km.ratio(y, num, den) - km.ratio(x, num, den), rng)
        return ra, rb, lo, hi

    out += ["| ukazatel | základ | rameno | rozdíl nebo poměr (95 %) | práh |", "|---|---:|---:|---|---|"]
    ra, n_a = fam_sum(sa, NI)
    rb, _ = fam_sum(sb, NI)
    lo, hi = km.boot(st, lambda x, y: fam_sum(y, NI)[0] - fam_sum(x, NI)[0], rng)
    out.append(f"| A1 správné rozhodnutí, rodiny kde síť nestačí (n = {n_a}) | {km.fmt(ra, True)} | {km.fmt(rb, True)} | {100*(rb-ra):+.1f} ({100*lo:+.1f} až {100*hi:+.1f}) p. b. | >= +10, dolní mez > 0 |".replace(".", ",").replace("p, b,", "p. b."))
    ra, rb, lo, hi = dr("sec_k", "sec_n")
    out.append(f"| A2 detekce bezpečnostních útoků | {km.fmt(ra, True)} | {km.fmt(rb, True)} | {100*(rb-ra):+.1f} ({100*lo:+.1f} až {100*hi:+.1f}) p. b. | >= +2, dolní mez > 0 |".replace(".", ",").replace("p, b,", "p. b."))
    fa, fb = km.ratio(sa, "fp", "days"), km.ratio(sb, "fp", "days")
    lo, hi = km.boot(st, lambda x, y: km.ratio(y, "fp", "days") / max(km.ratio(x, "fp", "days"), 1e-12), rng)
    out.append(f"| A3 zobrazené FP na síť-den | {km.fmt(fa)} | {km.fmt(fb)} | poměr {km.fmt(fb/max(fa,1e-12), d=3)} ({km.fmt(lo, d=3)} až {km.fmt(hi, d=3)}) | <= 1,10 |")
    wa = sum(i["wrong"] for i in sa)
    wb = sum(i["wrong"] for i in sb)
    na = sum(i["att_n"] for i in sa)
    nb = sum(i["att_n"] for i in sb)
    out.append(f"| A4 útoky s omylem zavřeným | {int(wa)} z {int(na)} | {int(wb)} z {int(nb)} (horní mez Wilson {100*wilson_hi(wb, nb):.2f} %) | rameno <= základ | `on100` <= `off` |".replace(".", ",").replace("p, b,", "p. b."))
    ra, rb, lo, hi = dr("hn_k", "hn_n")
    out.append(f"| A5 hn_* zobrazeno (nižší je lepší) | {km.fmt(ra, True)} | {km.fmt(rb, True)} | {100*(rb-ra):+.1f} ({100*lo:+.1f} až {100*hi:+.1f}) p. b. | <= -10 |".replace(".", ",").replace("p, b,", "p. b."))
    ea = [p[4] for p in pairs]
    eb = [p[5] for p in pairs]
    days = sum(i["virtual_days"] if "virtual_days" in i else 0 for i in sb)
    host_days = 0.0
    for p, eb_ in zip(pairs, eb):
        vd = (cand[p[0]].get("virtual_days") or 0)
        host_days += eb_["ep_hosts"] * vd
    bytes_total = sum(e["ep_bytes"] for e in eb)
    events_total = sum(e["ep_events"] for e in eb)
    per = bytes_total / host_days if host_days else float("nan")
    out.append(f"| A9 objem endpointových dat na host a den | - | {km.fmt(per / 1024, d=1)} KiB ({events_total} událostí) | - | <= 5 MiB |")
    # A6: podíl případů žebříku rozhodnutých autonomně (vyvráceno) a horní mez chyby (kontrafaktuální pravda)
    for lab, es in (("základ", ea), ("rameno", eb)):
        cases = sum(e["lat_n"] for e in es)
        ref = sum(e["refuted"] for e in es)
        wrong = sum(e["refuted_wrong"] for e in es)
        out.append(f"| A6 autonomně vyvráceno ({lab}) | - | {ref} z {cases} případů ({100*ref/max(cases,1):.1f} %) | omylem {wrong}, horní mez Wilson {100*wilson_hi(wrong, max(ref,1)):.2f} % | chyba <= 1 % |".replace(".", ","))
    la = sum(e["lat_sum"] for e in ea) / max(sum(e["lat_n"] for e in ea), 1)
    lb = sum(e["lat_sum"] for e in eb) / max(sum(e["lat_n"] for e in eb), 1)
    out.append(f"| A8 průměrná latence rozhodnutí žebříku (cykly na případ) | {km.fmt(la, d=2)} | {km.fmt(lb, d=2)} | - | rameno <= základ |")
    out += ["", "### Rodiny, kde síť nestačí (po rodinách)", "", "| rodina | n | základ | rameno | rozdíl p. b. (95 %) |", "|---|---:|---:|---:|---|"]
    for f in NI:
        r0, n0 = fam_sum(sa, [f])
        r1, _ = fam_sum(sb, [f])
        if n0 == 0:
            continue
        lo, hi = km.boot(st, lambda x, y, f=f: fam_sum(y, [f])[0] - fam_sum(x, [f])[0], rng)
        out.append(f"| {f} | {n0} | {km.fmt(r0, True)} | {km.fmt(r1, True)} | {100*(r1-r0):+.1f} ({100*lo:+.1f} až {100*hi:+.1f}) |".replace(".", ",").replace("p, b,", "p. b."))
    hn = sorted({f for i in sa for f in i["fam"] if f.startswith("hn_")})
    out += ["", "### hn_* po rodinách (zobrazeno, nižší je lepší)", "", "| rodina | n | základ | rameno |", "|---|---:|---:|---:|"]
    for f in hn:
        r0, n0 = fam_sum(sa, [f])
        r1, _ = fam_sum(sb, [f])
        out.append(f"| {f} | {n0} | {km.fmt(r0, True)} | {km.fmt(r1, True)} |")
    text = "\n".join(out) + "\n"
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text)
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)


main()
