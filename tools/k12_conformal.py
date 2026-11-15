#!/usr/bin/env python3
"""Krok 12: konformalni pokryti a hranice automatizace z `ladder_log` soak behu.

Kazdy radek `networks.jsonl` ma `output.ladder_log`: [posterior, utok(0/1), stav, cykly].
Sit se vzdy cela patri do kalibrace NEBO testu (rozdeleni po sitich, ne po pripadech;
pripady jedne site nejsou vymenitelne). Trida-podminena (Mondrian) konformalni
predikce jako `src/conformal.rs`: kvantil na poradi ceil((n+1)(1-alpha)).
Hlasi: empiricke pokryti utoku a neskodnych, podil autonomnich rozhodnuti (mnozina s
jedinou tridou), z autonomnich zavreni (neskodne) podil utoku s Wilson horni mezi,
a opakuje pro vice nahodnych rozdeleni siti.
Pouziti: python tools/k12_conformal.py DIR[,DIR] [--alpha-attack 0.05] [--alpha-benign 0.2]
"""
import argparse
import json
import math
import os
import random


def wilson_upper(k, n, z=1.96):
    if n == 0:
        return float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c + m


def quantile(sorted_scores, alpha):
    n = len(sorted_scores)
    rank = math.ceil((n + 1) * (1 - alpha))
    if rank == 0 or rank > n:
        return None
    return sorted_scores[rank - 1]


def load(dirs):
    nets = []
    for d in dirs:
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as h:
            for line in h:
                if line.strip():
                    log = json.loads(line)["output"].get("ladder_log") or []
                    if log:
                        nets.append(log)
    return nets


def one_split(nets, rng, a_atk, a_ben, min_per_class=50):
    idx = list(range(len(nets)))
    rng.shuffle(idx)
    half = len(idx) // 2
    cal = [r for i in idx[:half] for r in nets[i]]
    test = [r for i in idx[half:] for r in nets[i]]
    atk = sorted(1 - r[0] for r in cal if r[1] > 0.5)
    ben = sorted(r[0] for r in cal if r[1] <= 0.5)
    if len(atk) < min_per_class or len(ben) < min_per_class:
        return None
    qa, qb = quantile(atk, a_atk), quantile(ben, a_ben)
    res = dict(n=len(test), atk=0, ben=0, atk_cov=0, ben_cov=0, auto_ben=0, auto_ben_wrong=0, auto_atk=0, auto_atk_wrong=0, abstain=0)
    for p, y, *_ in test:
        has_atk = qa is None or (1 - p) <= qa
        has_ben = qb is None or p <= qb
        if y > 0.5:
            res["atk"] += 1
            res["atk_cov"] += has_atk
        else:
            res["ben"] += 1
            res["ben_cov"] += has_ben
        if has_ben and not has_atk:
            res["auto_ben"] += 1
            res["auto_ben_wrong"] += y > 0.5
        elif has_atk and not has_ben:
            res["auto_atk"] += 1
            res["auto_atk_wrong"] += y <= 0.5
        else:
            res["abstain"] += 1
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs")
    ap.add_argument("--alpha-attack", type=float, default=0.05)
    ap.add_argument("--alpha-benign", type=float, default=0.2)
    ap.add_argument("--splits", type=int, default=30)
    args = ap.parse_args()
    nets = load(args.dirs.split(","))
    rng = random.Random(12)
    tot = None
    used = 0
    covs = []
    for _ in range(args.splits):
        r = one_split(nets, rng, args.alpha_attack, args.alpha_benign)
        if not r:
            continue
        used += 1
        covs.append((r["atk_cov"] / max(r["atk"], 1), r["ben_cov"] / max(r["ben"], 1)))
        tot = r if tot is None else {k: tot[k] + r[k] for k in tot}
    if not tot:
        print("malo dat pro kalibraci")
        return
    n = tot["n"]
    print(f"siti {len(nets)}, rozdeleni {used}, pripadu v testech celkem {n}")
    print(f"nominalni pokryti utoku {1 - args.alpha_attack:.2f}, neskodnych {1 - args.alpha_benign:.2f}")
    print(f"empiricke pokryti utoku {tot['atk_cov'] / tot['atk']:.3f} (nejhorsi rozdeleni {min(c[0] for c in covs):.3f})")
    print(f"empiricke pokryti neskodnych {tot['ben_cov'] / tot['ben']:.3f} (nejhorsi {min(c[1] for c in covs):.3f})")
    print(f"autonomne rozhodnuto {100 * (n - tot['abstain']) / n:.1f} %, predano cloveku (abstence) {100 * tot['abstain'] / n:.1f} %")
    ab, aw = tot["auto_ben"], tot["auto_ben_wrong"]
    print(f"autonomni 'neskodne': {ab}, z nich utok {aw} ({100 * aw / max(ab, 1):.2f} %, horni mez Wilson {100 * wilson_upper(aw, ab):.2f} %)")
    aa, awa = tot["auto_atk"], tot["auto_atk_wrong"]
    print(f"autonomni 'utok': {aa}, z nich neskodne {awa} ({100 * awa / max(aa, 1):.2f} %, horni mez Wilson {100 * wilson_upper(awa, aa):.2f} %)")


if __name__ == "__main__":
    main()
