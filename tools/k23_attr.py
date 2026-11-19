#!/usr/bin/env python3
"""Krok 23: atribuce zdroje a zavaznost objemovych a nesparovanych nalezu proti pravde simulatoru.

Vstup: koren se stopami `<konfigurace>-<rameno>-<seed>.trace.jsonl` (K15_TRACE). Nalez typu
`inductive_volume_anomaly`, `packet_rate_spike` nebo `unmapped_passive_event` v cyklu c se priradi
pravdam aktivnim v c, jejichz cile (truth_cycle.targets, IP:port) obsahuji sluzbu nalezu. Tridy:
spravny (zdroje neprazdne a vsechny v pravdivych), cizi (aspon jeden mimo), zadny (bez zdroje).
Zavaznost: nalezy utoku (truths s kind attack:* v okne) objemovych typu po rodinach.
Kriteria K23-A1 az A3 a B1 (`docs/diplomka/eval/impl-krok23.md`, 1.5).

Pouziti: python -I tools/k23_attr.py KOREN [--pairs F2:F2S,FG2:FG2S]
"""
import argparse
import glob
import json
import os
from collections import Counter, defaultdict

VOLUME = ("inductive_volume_anomaly", "packet_rate_spike")
UNMAPPED = "unmapped_passive_event"


def service_target(service):
    parts = (service or "").split("/")
    if len(parts) != 3:
        return None
    return parts[0] + ":" + parts[2]


def scan(path):
    kind = {}
    active = defaultdict(list)
    finds = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if '"ev": "finding"' not in line and '"ev":"finding"' not in line and "truth" not in line:
                continue
            d = json.loads(line)
            ev = d.get("ev")
            if ev == "truth":
                kind[(d["net"], d["id"])] = d["kind"]
            elif ev == "truth_cycle":
                active[(d["net"], d["cycle"])].append(d)
            elif ev == "finding" and (d["type"] in VOLUME or d["type"] == UNMAPPED):
                finds.append(d)
    out = []
    for f in finds:
        target = service_target(f.get("service"))
        matched = [
            t for t in active.get((f["net"], f["cycle"]), []) if target and target in t["targets"]
        ]
        kinds = {kind.get((f["net"], t["id"]), "?") for t in matched}
        truth_src = set()
        for t in matched:
            truth_src |= set(t["sources"])
        src = set(f.get("sources") or [])
        if not matched:
            cls = "pozadi"
        elif not src:
            cls = "zadny"
        elif src <= truth_src:
            cls = "spravny"
        else:
            cls = "cizi"
        attack_fams = sorted(
            {t["kind"].split(":", 1)[1] for t in (f.get("truths") or []) if t["kind"].startswith("attack:") and t.get("in_window")}
        )
        out.append(
            {
                "type": f["type"],
                "cls": cls,
                "attack_target": any(k.startswith("attack:") for k in kinds),
                "kinds": kinds,
                "sev": f["severity"],
                "attack_fams": attack_fams,
                "key": (f["net"], f["cycle"], f["id"]),
            }
        )
    return out


def load(root):
    arms = defaultdict(list)
    for path in sorted(glob.glob(os.path.join(root, "*.trace.jsonl"))):
        name = os.path.basename(path)[: -len(".trace.jsonl")]
        cfg, arm, seed = name.rsplit("-", 2)
        for row in scan(path):
            row["cfg"] = cfg
            arms[arm].append(row)
    return arms


def shares(rows):
    c = Counter(r["cls"] for r in rows)
    judged = c["spravny"] + c["cizi"] + c["zadny"]
    pct = lambda k: 100.0 * c[k] / judged if judged else float("nan")  # noqa: E731
    return c, judged, pct


def line(label, rows):
    c, n, pct = shares(rows)
    return (
        f"{label}: n={n} spravny {c['spravny']} ({pct('spravny'):.1f} %), cizi {c['cizi']} ({pct('cizi'):.1f} %),"
        f" zadny {c['zadny']} ({pct('zadny'):.1f} %); pozadi {c['pozadi']}"
    ), pct, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--pairs", default="F2:F2S,FG2:FG2S")
    a = ap.parse_args()
    arms = load(a.root)
    for pair in a.pairs.split(","):
        base_arm, cand_arm = pair.split(":")
        base, cand = arms.get(base_arm, []), arms.get(cand_arm, [])
        if not base or not cand:
            continue
        cfgs = sorted({r["cfg"] for r in base} | {"*"})
        for cfg in cfgs:
            b = [r for r in base if cfg == "*" or r["cfg"] == cfg]
            c = [r for r in cand if cfg == "*" or r["cfg"] == cfg]
            print(f"== {cfg}: {cand_arm} proti {base_arm}")
            verdict = {}
            # A1: objemove nalezy s pravdou (vsechny druhy)
            vb = [r for r in b if r["type"] in VOLUME]
            vc = [r for r in c if r["type"] in VOLUME]
            lb, pb, _ = line(f"  A1 objem {base_arm}", vb)
            lc, pc, _ = line(f"  A1 objem {cand_arm}", vc)
            print(lb)
            print(lc)
            verdict["A1"] = pc("spravny") > pb("spravny") and pc("cizi") <= 0.5 * pb("cizi")
            for k in sorted({k for r in vb + vc for k in r["kinds"]}):
                _, pkb, nb = line("", [r for r in vb if k in r["kinds"]])
                _, pkc, nc = line("", [r for r in vc if k in r["kinds"]])
                print(
                    f"     {k}: spravny {pkb('spravny'):.1f} -> {pkc('spravny'):.1f} %, cizi {pkb('cizi'):.1f} -> {pkc('cizi'):.1f} %,"
                    f" zadny {pkb('zadny'):.1f} -> {pkc('zadny'):.1f} % (n {nb} -> {nc})"
                )
            # A2: objemove nalezy na cilech utoku
            ab = [r for r in vb if r["attack_target"]]
            ac = [r for r in vc if r["attack_target"]]
            lb, pb2, _ = line(f"  A2 utoky {base_arm}", ab)
            lc, pc2, _ = line(f"  A2 utoky {cand_arm}", ac)
            print(lb)
            print(lc)
            verdict["A2"] = not ab or pc2("spravny") >= pb2("spravny") - 1.0
            # A3: nesparovane
            ub = [r for r in b if r["type"] == UNMAPPED]
            uc = [r for r in c if r["type"] == UNMAPPED]
            lb, pb3, _ = line(f"  A3 nesparovane {base_arm}", ub)
            lc, pc3, nu = line(f"  A3 nesparovane {cand_arm}", uc)
            print(lb)
            print(lc)
            cnt = Counter(r["cls"] for r in uc)
            with_src = cnt["spravny"] + cnt["cizi"]
            right = 100.0 * cnt["spravny"] / with_src if with_src else float("nan")
            print(f"     se zdrojem {with_src}, z toho spravne {right:.1f} %")
            if nu:
                verdict["A3"] = pc3("zadny") < pb3("zadny") and (with_src < 20 or right >= 90.0)
            # B1: zavaznost nalezu utoku (objemove typy) po rodinach
            for arm, rows in ((base_arm, vb), (cand_arm, vc)):
                fam = defaultdict(Counter)
                for r in rows:
                    for f in r["attack_fams"]:
                        fam[f][r["sev"]] += 1
                text = ", ".join(
                    f"{f} H{v['High']}/M{v['Medium']}/L{v['Low']}" for f, v in sorted(fam.items())
                )
                print(f"  B1 zavaznost utoku {arm}: {text or 'zadne'}")
                if arm == cand_arm:
                    verdict["B1"] = sum(v["Low"] for v in fam.values()) == 0
            print("  verdikt: " + ", ".join(f"K23-{k} {'splneno' if v else 'NESPLNENO'}" for k, v in verdict.items()))


if __name__ == "__main__":
    main()
