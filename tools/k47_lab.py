#!/usr/bin/env python3
"""Krok 47: vlastní izolovaná laboratoř, skutečné útočné nástroje (nmap, curl, ssh, hydra),
skutečný Zeek záznam (ne syntetický generátor). Jde o zdroj-agnostický obal nad stávajícím
k33_corr.py harnessem (Zeek conn.log je nativní, žádný převod nepotřebuje).

  k47_lab.py eval --result DIR/result.json --runbook runbook.jsonl
"""
import importlib.util
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


k33 = load("k33_corr")
k35 = load("k35_corr")


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def load_runbook(path):
    """-> [{"chain": str, "ips": set, "phases": [...]}] (dva řetězce: skutečná kampaň a
    nezávislý druhý útočník)."""
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    chains = {}
    for r in rows:
        if "src" not in r:
            continue
        chain = "campaign" if r["src"] == "10.60.1.3" else "attacker2"
        c = chains.setdefault(chain, {"chain": chain, "ips": set(), "phases": []})
        c["ips"].update([r["src"], r["dst"]])
        t0 = ts(r["t0"]) if "t0" in r else None
        t1 = ts(r.get("t1", r.get("t0")))
        c["phases"].append({"phase": r["phase"], "stage": r.get("stage"), "actor": r["src"],
                            "peer": r["dst"], "t0": t0, "t1": t1})
    return list(chains.values())


def evaluate(res, runbook_path, window=1800):
    chains = load_runbook(runbook_path)
    shown = {f["id"]: f for f in res["shown"]}

    def chain_of(fid):
        ips = k33.ips_of(shown[fid]["text"])
        hit = [c["chain"] for c in chains if ips & c["ips"]]
        return hit[0] if len(hit) == 1 else (None if not hit else "ambiguous")
    label = {i: chain_of(i) for i in shown}
    campaign = {i for i, l in label.items() if l == "campaign"}
    attacker2 = {i for i, l in label.items() if l == "attacker2"}
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
    arms = {"B1": k33.groups_ip(res["shown"]), "B1b": k35.groups_ip_window(res["shown"]),
            "INC": [i["findings"] for i in inc], "INC_closure": list(clo.values())}
    out = {"shown": len(shown), "campaign_findings": len(campaign),
           "attacker2_findings": len(attacker2), "arms": {}}
    for name, groups in arms.items():
        groups = [g for g in groups if len(g) >= 2]
        ci = [g for g in groups if any(f in campaign for f in g)]
        tot = sum(len(g) for g in ci)
        non_campaign_non_bg = sum(1 for g in ci for f in g if f not in campaign and f not in attacker2 and label.get(f) is None)
        mixed_with_attacker2 = sum(1 for g in ci if any(f in attacker2 for f in g))
        out["arms"][name] = {
            "incidents_total": len(groups), "campaign_incidents": len(ci),
            "completeness": max((sum(1 for f in g if f in campaign) for g in ci), default=0) / len(campaign) if campaign else 0,
            "mixed_with_independent_attacker2": mixed_with_attacker2,
            "background_noise_in_campaign_incidents": non_campaign_non_bg,
            "largest_incident": max((len(g) for g in groups), default=0)}
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--conn", required=True)
    r.add_argument("--bin", required=True)
    r.add_argument("--work", required=True)
    r.add_argument("--scope", default="10.60.2.0/29,10.60.3.0/29,10.60.4.0/29,10.60.5.0/29,10.60.6.0/29")
    r.add_argument("--window", type=int, default=120)
    r.add_argument("--v3-on", default="")
    r.add_argument("--env", action="append", default=[])
    e = sub.add_parser("eval")
    e.add_argument("--result", required=True)
    e.add_argument("--runbook", required=True)
    a = ap.parse_args()
    if a.cmd == "run":
        k33.cmd_run(a)
    else:
        print(json.dumps(evaluate(json.load(open(a.result, encoding="utf-8")), a.runbook),
                         indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
