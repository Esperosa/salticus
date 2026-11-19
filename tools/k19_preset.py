#!/usr/bin/env python3
"""Krok 19, cast A: preset `recommended()` proti kandidatovi (+ endpoint_weak, refute_episode,
confirm_evidence), parove po konfiguracich site.

Vstup: koren sady (`<konfigurace>-base-<seed>`, `<konfigurace>-cand-<seed>`, v kazdem
`networks.jsonl`). Paruje se podle (seed, sit). Vypisuje predregistrovana kriteria K19-A1 az A5
(impl-krok19.md) a verdikt po konfiguracich.

Pouziti: python tools/k19_preset.py KOREN [--min-family 20] [--boot 2000]
Bez zavislosti mimo standardni knihovnu.
"""
import argparse
import glob
import json
import math
import os
import random
from collections import defaultdict


def load(path):
    rows = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                rows[(row["run_seed"], row["network_id"])] = row
    return rows


def arms(root):
    out = defaultdict(lambda: {"base": {}, "cand": {}})
    for d in sorted(glob.glob(os.path.join(root, "*-*-*"))):
        path = os.path.join(d, "networks.jsonl")
        if not os.path.isfile(path):
            continue
        cfg, arm, _seed = os.path.basename(d).rsplit("-", 2)
        out[cfg][arm].update(load(path))
    return out


def metrics(row):
    o = row["output"]
    fams = row.get("families", {})
    return {
        "truth": sum(f.get("truth", 0) for f in fams.values()),
        "det": sum(f.get("detected_displayed", 0) for f in fams.values()),
        "fp": o.get("displayed_fp", 0),
        "human": o.get("ladder_confirmed", 0) + o.get("ladder_escalated", 0),
        "wrong": o.get("auto_closures_wrong", 0) + o.get("ladder_refuted_wrong_cf", 0),
        "auto_closed": o.get("auto_closures", 0),
        "refuted": o.get("ladder_refuted", 0),
        "conf": o.get("ladder_confirmed", 0),
        "esc": o.get("ladder_escalated", 0),
        "days": row.get("virtual_days", 0),
    }


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


def wilson_upper(k, n, z=1.959964):
    if n == 0:
        return float("nan")
    p = k / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + half) / den


def bootstrap(base, cand, keys, n_boot, seed):
    """Parovy bootstrap po sitich stratifikovany podle seedu: interval rozdilu detekce (p. b.)
    a relativni zmeny FP a pripadu pro cloveka."""
    strata = defaultdict(list)
    for k in keys:
        strata[k[0]].append(k)
    rng = random.Random(seed)
    det, fp, human = [], [], []
    for _ in range(n_boot):
        sample = []
        for ks in strata.values():
            sample.extend(rng.choice(ks) for _ in ks)
        b, _ = total(base, sample)
        c, _ = total(cand, sample)
        if b["truth"]:
            det.append(100.0 * (c["det"] - b["det"]) / b["truth"])
        if b["fp"]:
            fp.append(c["fp"] / b["fp"] - 1.0)
        if b["human"]:
            human.append(c["human"] / b["human"] - 1.0)

    def ci(xs):
        xs = sorted(xs)
        if not xs:
            return (float("nan"), float("nan"))
        return xs[int(0.025 * len(xs))], xs[min(len(xs) - 1, int(0.975 * len(xs)))]

    return ci(det), ci(fp), ci(human)


def pct(a, b):
    return 100.0 * a / b if b else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--min-family", type=int, default=20)
    ap.add_argument("--boot", type=int, default=2000)
    args = ap.parse_args()
    verdict = {}
    for cfg, pair in sorted(arms(args.root).items()):
        keys = sorted(set(pair["base"]) & set(pair["cand"]))
        unpaired = len(set(pair["base"]) ^ set(pair["cand"]))
        b, fb = total(pair["base"], keys)
        c, fc = total(pair["cand"], keys)
        print(f"== {cfg}: {len(keys)} paru sit (nesparovano {unpaired}), {b['days']:.0f} sit-dni, {b['truth']:.0f} utoku")
        for label, s in (("zaklad", b), ("kandidat", c)):
            print(
                f"  {label}: detekce {pct(s['det'], s['truth']):.2f} %, zobrazene FP {s['fp']:.0f}, pro cloveka {s['human']:.0f} "
                f"(potvrzeno {s['conf']:.0f}, eskalovano {s['esc']:.0f}), vyvraceno {s['refuted']:.0f}, auto zavreno {s['auto_closed']:.0f}, "
                f"omylem zavreno {s['wrong']:.0f} (Wilson horni mez {100 * wilson_upper(s['wrong'], s['truth']):.3f} %)"
            )
        ok = {}
        ok["A1"] = c["wrong"] == 0
        drops = []
        for name in sorted(fb):
            truth, det_b = fb[name]
            det_c = fc[name][1]
            if truth >= args.min_family and det_b != det_c:
                diff = pct(det_c, truth) - pct(det_b, truth)
                mark = "  <-- pokles > 1 p. b." if diff < -1.0 else ""
                if diff < -1.0:
                    drops.append(name)
                print(f"    {name}: {pct(det_b, truth):.1f} -> {pct(det_c, truth):.1f} % (n = {truth}){mark}")
        ok["A2"] = not drops
        fp_ratio = c["fp"] / b["fp"] if b["fp"] else float("nan")
        ok["A3"] = fp_ratio <= 1.01
        human = c["human"] / b["human"] - 1.0 if b["human"] else float("nan")
        ok["A4"] = human <= 0.02
        (d_lo, d_hi), (f_lo, f_hi), (h_lo, h_hi) = bootstrap(pair["base"], pair["cand"], keys, args.boot, 19)
        ok["A5"] = d_hi >= 0 and f_lo <= 0 and h_lo <= 0
        print(
            f"  FP pomer {fp_ratio:.4f}; pripady pro cloveka {100 * human:+.2f} %; detekce {pct(c['det'] - b['det'], b['truth']):+.2f} p. b."
        )
        print(
            f"  bootstrap 95 %: detekce [{d_lo:+.2f}; {d_hi:+.2f}] p. b., FP [{100 * f_lo:+.2f}; {100 * f_hi:+.2f}] %, "
            f"pro cloveka [{100 * h_lo:+.2f}; {100 * h_hi:+.2f}] %"
        )
        print("  kriteria: " + ", ".join(f"{k} {'splneno' if v else 'NESPLNENO'}" for k, v in ok.items()))
        verdict[cfg] = all(ok.values())
    print("VERDIKT: " + ("zmenit recommended()" if verdict and all(verdict.values()) else "recommended() beze zmeny") + f" {verdict}")


if __name__ == "__main__":
    main()
