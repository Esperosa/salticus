#!/usr/bin/env python3
"""Krok 36: korelace na DARPA 2000 LLDOS (jedna vícefázová kampaň se skutečnou pravdou po fázích).

  k36_lldos.py run  --conn zeek/conn.log --bin salticus-program.exe --work DIR [--v3-on ...]
  k36_lldos.py eval --result DIR/result.json --lists DIR_s_phase-N.list [--window 1800]

Pravda: soubory `phase-N.list` (relace pravdy po fázích; adresy s nulami zleva, čas lokální
EST = UTC-5). Řetězec = adresy kampaně ze všech pěti seznamů (bez 0.0.0.0 a broadcastu). Nález
patří kampani, jen když zmiňuje adresu kampaně. Fáze nálezu: fáze, jejíž interval ±30 min
obsahuje čas prvního zobrazení nálezu. Jde o případovou studii (jedna kampaň), ne o statistiku.
"""
import argparse
import importlib.util
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("k33_corr", os.path.join(HERE, "k33_corr.py"))
k33 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k33)
spec2 = importlib.util.spec_from_file_location("k35_corr", os.path.join(HERE, "k35_corr.py"))
k35 = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(k35)

IGNORE = {"0.0.0.0", "255.255.255.255"}


def norm_ip(s):
    return ".".join(str(int(p)) for p in s.split("."))


def parse_lists(dirpath):
    """-> (adresy kampaně, {fáze: (t_start, t_end)}) v epoch UTC."""
    ips, phases = set(), {}
    count = defaultdict(int)
    for n in range(1, 6):
        path = os.path.join(dirpath, f"phase-{n}.list")
        times = []
        for line in open(path, encoding="utf-8", errors="replace"):
            p = line.split()
            if len(p) < 9 or not re.match(r"\d\d/\d\d/\d{4}", p[1]):
                continue
            local = datetime.strptime(p[1] + " " + p[2], "%m/%d/%Y %H:%M:%S")
            # lokální čas USA východ: od 2. 4. 2000 letní čas (UTC-4), před ním UTC-5
            hours = 4 if local >= datetime(2000, 4, 2) else 5
            ts = local.replace(tzinfo=timezone.utc) + timedelta(hours=hours)
            times.append(ts.timestamp())
            for a in (p[7], p[8]):
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", a):
                    count[norm_ip(a)] += 1
                    ips.add(norm_ip(a))
        if times:
            phases[n] = (min(times), max(times))
    # podvržené zdroje záplavy (jednorázové adresy v seznamu) kampaň neurčují
    if len(ips) >= 50:
        ips = {a for a in ips if count[a] >= 2}
    return ips - IGNORE, phases


def groups_of(res, arm):
    shown = res["shown"]
    if arm == "B1":
        return k33.groups_ip(shown)
    if arm == "B1b":
        return k35.groups_ip_window(shown)
    if arm == "INC_closure":
        # incidenty spojené odkazem `related` tvoří jednu skupinu (uzávěr), samotné incidenty se
        # neslučují; měří se úplnost, kterou analytik dostane přes odkazy
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
        out = defaultdict(list)
        for n, i in enumerate(inc):
            out[find(n)].extend(i["findings"])
        return list(out.values())
    return [i["findings"] for i in res["incidents"]]


def evaluate(res, lists_dir, window):
    ips, phases = parse_lists(lists_dir)
    shown = {f["id"]: f for f in res["shown"]}
    chain = {i for i, f in shown.items() if k33.ips_of(f["text"]) & ips}

    def phase_of(f):
        t = shown[f]["t"]
        return {n for n, (a, b) in phases.items() if a - window <= t <= b + window}
    out = {"campaign_ips": sorted(ips), "phases": {n: [a, b] for n, (a, b) in phases.items()},
           "shown": len(shown), "chain_findings": len(chain), "arms": {}}
    for arm in ("B1", "B1b", "INC", "INC_closure"):
        groups = [g for g in groups_of(res, arm) if len(g) >= 2]
        ci = [g for g in groups if any(f in chain for f in g)]
        sizes = [len(g) for g in ci]
        in_ci = sum(sizes)
        non = sum(1 for g in ci for f in g if f not in chain)
        best = max(ci, key=lambda g: len({p for f in g if f in chain for p in phase_of(f)}), default=[])
        cov = {p for f in best if f in chain for p in phase_of(f)}
        out["arms"][arm] = {
            "incidents_total": len(groups),
            "chain_incidents": len(ci),
            "completeness": max((sum(1 for f in g if f in chain) for g in ci), default=0) / len(chain) if chain else 0,
            "phases_covered_best": sorted(cov),
            "contamination": non / in_ci if in_ci else 0.0,
            "largest_incident": max((len(g) for g in groups), default=0),
            "background_incidents": len(groups) - len(ci)}
    out["chain_by_phase"] = {n: sum(1 for f in chain if n in phase_of(f)) for n in phases}
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--conn", required=True)
    r.add_argument("--bin", required=True)
    r.add_argument("--work", required=True)
    r.add_argument("--scope", default="172.16.0.0/16")
    r.add_argument("--window", type=int, default=1800)
    r.add_argument("--v3-on", default="")
    r.add_argument("--env", action="append", default=[])
    e = sub.add_parser("eval")
    e.add_argument("--result", required=True)
    e.add_argument("--lists", required=True)
    e.add_argument("--window", type=int, default=1800)
    a = ap.parse_args()
    if a.cmd == "run":
        k33.cmd_run(a)
    else:
        res = json.load(open(a.result, encoding="utf-8"))
        print(json.dumps(evaluate(res, a.lists, a.window), indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
