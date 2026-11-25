#!/usr/bin/env python3
"""Krok 35: vyhodnocení korelace se silnějšími baseline a metrikou kontaminace.

  k35_corr.py eval --result result.json --truth truth.json [--result2 jiný běh]

Navíc proti kroku 33: baseline B1b (spojení podle sdílené IP s oknem 6 h a mezí hubu 25),
kontaminace incidentů s řetězcem nálezy pozadí, počet čistě pozaďových incidentů za den, churn
incidentů po oknech (nálezy, které se mezi sousedními okny přesunuly do jiného incidentu).
Běh `run` je z k33_corr.py (ukládá i snapshoty incidentů po oknech).
"""
import argparse
import importlib.util
import json
import os
import random
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("k33_corr", os.path.join(HERE, "k33_corr.py"))
k33 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k33)

GAP = 6 * 3600
HUB = 25


def groups_ip_window(findings):
    """B1b: sdílená IP spojuje, ale jen do odstupu 6 h a dokud IP nespojila 25 nálezů."""
    order = sorted(range(len(findings)), key=lambda i: findings[i]["t"])
    parent = list(range(len(findings)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    last = {}
    for i in order:
        for ip in k33.ips_of(findings[i]["text"]):
            if ip in last:
                j, used = last[ip]
                if findings[i]["t"] - findings[j]["t"] <= GAP and used < HUB:
                    parent[find(i)] = find(j)
                    last[ip] = (i, used + 1)
                    continue
                last[ip] = (i, 1)
            else:
                last[ip] = (i, 1)
    out = defaultdict(list)
    for i in range(len(findings)):
        out[find(i)].append(findings[i]["id"])
    return list(out.values())


def contamination(groups, shown, truth):
    """Podíl nálezů pozadí (bez IP z pravdy) v incidentech, které obsahují aspoň jeden nález
    řetězce; a počet incidentů čistě z pozadí."""
    own = set()
    for c in truth:
        own |= set(c.get("all_ips", c["ips"] + [c["ext"]]))
    chain_f = {f["id"]: bool(k33.ips_of(f["text"]) & own) for f in shown}
    in_chain_inc = bg_in = pure_bg = 0
    for g in groups:
        flags = [chain_f.get(f, False) for f in g]
        if len(g) < 2:
            continue
        if any(flags):
            in_chain_inc += len(g)
            bg_in += sum(1 for x in flags if not x)
        else:
            pure_bg += 1
    return {"contamination": (bg_in / in_chain_inc) if in_chain_inc else 0.0,
            "background_in_chain_incidents": bg_in, "pure_background_incidents": pure_bg}


def churn(snapshots):
    """Podíl nálezů, které se mezi sousedními okny přesunuly do incidentu s jiným členstvím
    (nejen rozšířeným): nález byl v incidentu I a v dalším okně je v incidentu J, který neobsahuje
    celé I."""
    moved = total = 0
    for a, b in zip(snapshots, snapshots[1:]):
        where_b = {}
        for inc in b["incidents"]:
            for f in inc["findings"]:
                where_b[f] = set(inc["findings"])
        for inc in a["incidents"]:
            fs = set(inc["findings"])
            for f in fs:
                total += 1
                if f in where_b and not fs <= where_b[f]:
                    moved += 1
    return {"moved": moved, "total": total, "rate": moved / total if total else 0.0}


def evaluate(res, truth, seed):
    shown = res["shown"]
    label_of = {f["id"]: k33.chain_of(f["text"], truth) for f in shown}
    arms = {"B0_each": [[f["id"]] for f in shown],
            "B1_ip": k33.groups_ip(shown),
            "B1b_ip_window": groups_ip_window(shown),
            "INC_report": [i["findings"] for i in res["incidents"]]}
    sizes = [len(g) for g in arms["B1_ip"]]
    ids = [f["id"] for f in shown]
    random.Random(seed).shuffle(ids)
    b2, pos = [], 0
    for s in sizes:
        b2.append(ids[pos:pos + s])
        pos += s
    arms["B2_random"] = b2
    inc = res["incidents"]
    idx = {i.get("key"): n for n, i in enumerate(inc)}
    parent = list(range(len(inc)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for n, i in enumerate(inc):
        for r in i.get("related", []):
            if r["key"] in idx:
                parent[find(n)] = find(idx[r["key"]])
    clo = defaultdict(list)
    for n, i in enumerate(inc):
        clo[find(n)].extend(i["findings"])
    arms["INC_closure"] = list(clo.values())
    out = {"shown": len(shown), "incidents": len(res["incidents"]), "arms": {}}
    stats = {}
    for name, groups in arms.items():
        m = k33.metrics(groups, truth, label_of)
        m.update(contamination(groups, shown, truth))
        out["arms"][name] = m
        stats[name] = k33.pair_stats(groups, label_of)
    base = "B1b_ip_window"
    stats2 = dict(stats)
    stats2["B1_ip"] = stats[base]  # rozdíly se počítají proti silnější baseline
    out["bootstrap_vs_B1b"] = k33.cluster_bootstrap(truth, stats2)
    out["bootstrap_vs_B1"] = k33.cluster_bootstrap(truth, stats)
    out["churn"] = churn(res.get("snapshots", []))
    by = defaultdict(dict)
    for variant in sorted({c["variant"] for c in truth}):
        sub = [c for c in truth if c["variant"] == variant]
        by[variant] = {name: round(k33.metrics(groups, sub, {f: l & {c["chain"] for c in sub}
                                                              for f, l in label_of.items()})["pair_f1"], 3)
                       for name, groups in arms.items() if name != "B0_each"}
    out["f1_by_variant"] = by
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("eval")
    e.add_argument("--result", required=True)
    e.add_argument("--truth", required=True)
    e.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    res = json.load(open(a.result, encoding="utf-8"))
    truth = json.load(open(a.truth, encoding="utf-8"))
    print(json.dumps(evaluate(res, truth, a.seed), indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
