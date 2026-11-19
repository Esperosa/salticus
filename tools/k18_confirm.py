#!/usr/bin/env python3
"""Krok 18: politika potvrzování žebříku, párové srovnání základ/kandidát po konfiguracích.

Vstup: kořen sady (`<konfigurace>-base-<seed>`, `<konfigurace>-cand-<seed>`, v každém
`networks.jsonl`). Páruje se podle (seed, síť). Vypisuje K18-1 (podíl potvrzení bez důkazu
z nezávislého zdroje), K18-3 (omylem zavřené), K18-4 (nepotvrzené předané člověku, celkem
případů pro člověka), K18-5 (přesnost potvrzení), K18-6 (zobrazené FP) a detekci po rodinách
(zobrazeno; rodiny s >= 20 útoky, změna > 1 p. b. se označí).

Použití: python tools/k18_confirm.py KOREN [--min-family 20]
Bez závislostí mimo standardní knihovnu.
"""
import argparse
import glob
import json
import os
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


def summary(rows, keys):
    s = defaultdict(float)
    fam = defaultdict(lambda: [0, 0])
    for key in keys:
        r = rows[key]
        o = r["output"]
        k18 = o.get("ladder_k18", {})
        s["days"] += r.get("virtual_days", 0)
        s["conf"] += o.get("ladder_confirmed", 0)
        s["conf_att"] += o.get("ladder_confirmed_attack", 0)
        s["esc"] += o.get("ladder_escalated", 0)
        s["ref"] += o.get("ladder_refuted", 0)
        s["prior_only"] += k18.get("confirmed_prior_only", 0)
        s["dep_only"] += k18.get("confirmed_dep_only", 0)
        s["held"] += k18.get("prior_held", 0)
        s["held_att"] += k18.get("prior_held_attack", 0)
        s["hold_refused"] += k18.get("hold_refused", 0)
        s["hold_refused_att"] += k18.get("hold_refused_attack", 0)
        s["wrong"] += o.get("auto_closures_wrong", 0) + o.get("ladder_refuted_wrong_cf", 0)
        s["displayed_fp"] += o.get("displayed_fp", 0)
        s["displayed"] += o.get("displayed", 0)
        for name, f in r.get("families", {}).items():
            fam[name][0] += f.get("truth", 0)
            fam[name][1] += f.get("detected_displayed", 0)
    return s, fam


def pct(a, b):
    return 100.0 * a / b if b else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--min-family", type=int, default=20)
    args = ap.parse_args()
    for cfg, pair in sorted(arms(args.root).items()):
        keys = sorted(set(pair["base"]) & set(pair["cand"]))
        unpaired = len(set(pair["base"]) ^ set(pair["cand"]))
        b, fb = summary(pair["base"], keys)
        c, fc = summary(pair["cand"], keys)
        print(f"== {cfg}: {len(keys)} paru sit (nesparovano {unpaired}), {b['days']:.0f} sit-dni")
        for label, s in (("zaklad", b), ("kandidat", c)):
            bad = s["prior_only"] + s["dep_only"]
            print(
                f"  {label}: potvrzeno {s['conf']:.0f} (bez nezav. dukazu {bad:.0f} = {pct(bad, s['conf']):.1f} %: "
                f"jen prior {s['prior_only']:.0f}, jen zavisly {s['dep_only']:.0f}), presnost {pct(s['conf_att'], s['conf']):.1f} %; "
                f"eskalovano {s['esc']:.0f}; nepotvrzeno predano {s['held']:.0f} (utok {pct(s['held_att'], s['held']):.1f} %, "
                f"{s['held'] / s['days'] if s['days'] else 0:.2f}/sit-den); drzeni odmitlo vyvraceni {s['hold_refused']:.0f} "
                f"(utok {s['hold_refused_att']:.0f}); vyvraceno {s['ref']:.0f}; omylem zavreno {s['wrong']:.0f}; "
                f"pro cloveka {s['conf'] + s['esc']:.0f}; zobrazeno {s['displayed']:.0f}, z toho FP {s['displayed_fp']:.0f}"
            )
        human_b, human_c = b["conf"] + b["esc"], c["conf"] + c["esc"]
        print(
            f"  pripady pro cloveka: {pct(human_c - human_b, human_b):+.2f} %; FP pomer {c['displayed_fp'] / b['displayed_fp'] if b['displayed_fp'] else float('nan'):.4f}"
        )
        tb = sum(v[0] for v in fb.values())
        db, dc = sum(v[1] for v in fb.values()), sum(v[1] for v in fc.values())
        print(f"  detekce celkem {pct(db, tb):.2f} -> {pct(dc, tb):.2f} % ({tb} utoku)")
        for name in sorted(fb):
            truth, det_b = fb[name]
            det_c = fc[name][1]
            if truth >= args.min_family and det_b != det_c:
                diff = pct(det_c, truth) - pct(det_b, truth)
                mark = "  <-- pokles > 1 p. b." if diff < -1.0 else ""
                print(f"    {name}: {pct(det_b, truth):.1f} -> {pct(det_c, truth):.1f} % (n = {truth}){mark}")


if __name__ == "__main__":
    main()
