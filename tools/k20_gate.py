#!/usr/bin/env python3
"""Krok 20: jedina brana zavreni, parove srovnani ramen po konfiguracich site.

Vstup: jeden nebo vic korenu se slozkami `<konfigurace>-<rameno>-<seed>` (v kazde
`networks.jsonl`). Ramena: R (recommended), RG (R + close_gate), F (final), FG (F + close_gate).
`--alias base=R` prejmenuje rameno (napr. zakladni behy kroku 19). Paruje se podle (seed, sit).
Vypisuje predregistrovana kriteria K20-1 az K20-4 (`docs/diplomka/eval/impl-krok20.md`).

Pouziti: python tools/k20_gate.py KOREN [KOREN ...] [--alias base=R] [--boot 2000]
Bez zavislosti mimo standardni knihovnu.
"""
import argparse
import glob
import json
import math
import os
import random
from collections import defaultdict

PAIRS = [("R", "RG"), ("F", "FG")]


def wilson_upper(k, n, z=1.959964):
    if n == 0:
        return float("nan")
    p = k / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + half) / den


def metrics(row):
    o = row["output"]
    fams = row.get("families", {})
    attacks = row.get("attacks", [])
    k7 = o.get("k7", {})
    hidden = 0
    for a in attacks:
        h = (a.get("diag") or {}).get("hidden", {})
        if h.get("state_refuted", 0) > 0 or h.get("state_auto_resolved", 0) > 0:
            hidden += 1
    return {
        "truth": sum(f.get("truth", 0) for f in fams.values()),
        "det": sum(f.get("detected_displayed", 0) for f in fams.values()),
        "fp": o.get("displayed_fp", 0),
        "human": o.get("ladder_confirmed", 0) + o.get("ladder_escalated", 0),
        "wrong": o.get("auto_closures_wrong", 0) + o.get("ladder_refuted_wrong_cf", 0),
        "wrong_auto": o.get("auto_closures_wrong", 0),
        "wrong_auto_cf": o.get("auto_closures_wrong_cf", 0),
        "wrong_ladder": o.get("ladder_refuted_wrong_cf", 0),
        "att_wrong": sum(1 for a in attacks if ((a.get("k7") or {}).get("wrong_closed", 0) > 0)),
        "att_hidden": hidden,
        "attacks": len(attacks),
        "auto_closed": o.get("auto_closures", 0),
        "refuted": o.get("ladder_refuted", 0),
        "gate_bypass": k7.get("gate_bypass", 0),
        "gate_violations": k7.get("gate_violations", 0),
        "panics": row.get("panics", 0),
    }


def load(roots, alias):
    out = defaultdict(lambda: defaultdict(dict))
    for root in roots:
        for d in sorted(glob.glob(os.path.join(root, "*-*-*"))):
            path = os.path.join(d, "networks.jsonl")
            if not os.path.isfile(path):
                continue
            cfg, arm, _seed = os.path.basename(d).rsplit("-", 2)
            arm = alias.get(arm, arm)
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        row = json.loads(line)
                        out[cfg][arm][(row["run_seed"], row["network_id"])] = row
    return out


def total(rows, keys):
    s = defaultdict(float)
    fam = defaultdict(lambda: [0, 0])
    for k in keys:
        for name, v in metrics(rows[k]).items():
            s[name] += v
        for name, f in rows[k].get("families", {}).items():
            fam[name][0] += f.get("truth", 0)
            fam[name][1] += f.get("detected_displayed", 0)
    return s, fam


def bootstrap(base, cand, keys, boot, seed=20):
    rng = random.Random(seed)
    by_seed = defaultdict(list)
    for k in keys:
        by_seed[k[0]].append(k)
    det, fp, hum = [], [], []
    for _ in range(boot):
        sample = []
        for ks in by_seed.values():
            sample += [ks[rng.randrange(len(ks))] for _ in ks]
        b, _ = total(base, sample)
        c, _ = total(cand, sample)
        if b["truth"] and c["truth"]:
            det.append(100 * (c["det"] / c["truth"] - b["det"] / b["truth"]))
        if b["fp"]:
            fp.append(100 * (c["fp"] / b["fp"] - 1))
        if b["human"]:
            hum.append(100 * (c["human"] / b["human"] - 1))

    def ci(v):
        v = sorted(v)
        if not v:
            return (float("nan"), float("nan"))
        return (v[int(0.025 * len(v))], v[min(len(v) - 1, int(0.975 * len(v)))])

    return ci(det), ci(fp), ci(hum)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("roots", nargs="+")
    ap.add_argument("--alias", action="append", default=[])
    ap.add_argument("--boot", type=int, default=2000)
    ap.add_argument("--min-family", type=int, default=20)
    a = ap.parse_args()
    alias = dict(x.split("=", 1) for x in a.alias)
    data = load(a.roots, alias)
    for cfg in sorted(data):
        for base_arm, cand_arm in PAIRS:
            base, cand = data[cfg].get(base_arm, {}), data[cfg].get(cand_arm, {})
            keys = sorted(set(base) & set(cand))
            if not keys:
                continue
            unpaired = len(set(base) ^ set(cand))
            b, bf = total(base, keys)
            c, cf = total(cand, keys)
            print(f"== {cfg}: {cand_arm} proti {base_arm} ({len(keys)} paru siti, nesparovano {unpaired})")
            n = c["truth"]
            print(
                f"  K20-1  omylem zavreno (rozhodnuti) {b['wrong']:.0f} -> {c['wrong']:.0f}"
                f" (auto {b['wrong_auto']:.0f}->{c['wrong_auto']:.0f}, cf {b['wrong_auto_cf']:.0f}->{c['wrong_auto_cf']:.0f};"
                f" zebrik {b['wrong_ladder']:.0f}->{c['wrong_ladder']:.0f}); Wilson kandidata {100 * wilson_upper(c['wrong'], n):.3f} % z {n:.0f}"
            )
            na = c["attacks"]
            print(
                f"  K20-1b utoky s omylem zavrenym nalezem {b['att_wrong']:.0f} -> {c['att_wrong']:.0f}"
                f" (Wilson {100 * wilson_upper(c['att_wrong'], na):.3f} % z {na:.0f})"
            )
            print(f"  K20-1c utoky pohlcene pod zavrenym klicem {b['att_hidden']:.0f} -> {c['att_hidden']:.0f}")
            (dlo, dhi), (flo, fhi), (hlo, hhi) = bootstrap(base, cand, keys, a.boot)
            dd = 100 * (c["det"] / c["truth"] - b["det"] / b["truth"])
            print(
                f"  K20-2  detekce {100 * b['det'] / b['truth']:.2f} -> {100 * c['det'] / c['truth']:.2f} %"
                f" ({dd:+.2f} p. b., 95% [{dlo:+.2f}; {dhi:+.2f}])"
            )
            drops = []
            for name, (t, d) in sorted(bf.items()):
                if t >= a.min_family and name in cf:
                    ct, cd = cf[name]
                    diff = 100 * (cd / ct - d / t)
                    if diff < -1.0:
                        drops.append(f"{name} {100 * d / t:.1f}->{100 * cd / ct:.1f} (n={t})")
            print(f"  K20-2  rodiny s poklesem > 1 p. b.: {', '.join(drops) if drops else 'zadna'}")
            ratio = c["fp"] / b["fp"] if b["fp"] else float("nan")
            print(f"  K20-3  zobrazene FP {b['fp']:.0f} -> {c['fp']:.0f} (x{ratio:.4f}; 95% [{flo:+.2f}; {fhi:+.2f}] %)")
            hr = 100 * (c["human"] / b["human"] - 1) if b["human"] else float("nan")
            print(f"  K20-4  pripady pro cloveka {b['human']:.0f} -> {c['human']:.0f} ({hr:+.2f} %, 95% [{hlo:+.2f}; {hhi:+.2f}])")
            print(
                f"  dalsi: auto zavreno {b['auto_closed']:.0f}->{c['auto_closed']:.0f}, vyvraceno {b['refuted']:.0f}->{c['refuted']:.0f},"
                f" obchvat brany {c['gate_bypass']:.0f}, poruseni invariantu {c['gate_violations']:.0f}, paniky {c['panics']:.0f}"
            )
            ok = {
                "1": c["wrong"] == 0,
                "1b": c["att_wrong"] == 0,
                "1c": c["att_hidden"] <= b["att_hidden"],
                "2": not drops and dhi > -1.0,
                "3": ratio <= 1.02,
                "4": hr <= 2.0,
            }
            print("  verdikt: " + ", ".join(f"K20-{k} {'splneno' if v else 'NESPLNENO'}" for k, v in ok.items()))


if __name__ == "__main__":
    main()
