#!/usr/bin/env python3
"""Krok 13, bod 3: offline ladění seskupení nálezů do incidentů nad exportem soaku.

Vstup: `K13_INC_DUMP` soru (jsonl, jeden řádek = síť, události s polem label = pravda
nebo null). Metrika čistoty je stejná jako v soaku: incidenty s >= 2 nálezy, nález bez
pravdy je vlastní štítek (best = max(nejpočetnější pravda, 1 pokud je nějaký bez pravdy)).
Navíc: podíl nálezů v incidentech >= 2 (proti triviálnímu rozdělení) a úplnost
(podíl dvojic nálezů téže pravdy, které skončily ve stejném incidentu).
Pozor: `fault` (pravda je porucha) se NIKDY nepoužívá při seskupování, jen label k měření.

Pouziti: python -I tools/k13_incidents.py DUMP.jsonl
"""
import collections
import itertools
import json
import sys

TACTICS = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery",
           "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]


def groups(events, gap, hub=None, same_kind=False, max_span=None, need_two_keys=False):
    n = len(events)
    order = sorted(range(n), key=lambda i: events[i]["ts"])
    deg = collections.Counter()
    for e in events:
        for k in ["h:" + e["host"]] + ["i:" + x for x in e["ind"]]:
            deg[k] += 1
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    start = {i: events[i]["ts"] for i in range(n)}
    last = {}
    for i in order:
        e = events[i]
        for k in ["h:" + e["host"]] + ["i:" + x for x in e["ind"]]:
            if hub is not None and deg[k] > hub:
                continue
            key = (k, e["kind"]) if same_kind else k
            j = last.get(key)
            if j is not None and e["ts"] - events[j]["ts"] <= gap:
                a, b = find(i), find(j)
                if a != b:
                    if max_span is not None:
                        ma = min(start[x] for x in (a, b))
                        # rozpětí po sloučení se kontroluje přibližně přes kořeny
                        if e["ts"] - ma > max_span:
                            last[key] = i
                            continue
                    parent[a] = b
                    start[b] = min(start[a], start[b])
            last[key] = i
    g = collections.defaultdict(list)
    for i in range(n):
        g[find(i)].append(i)
    return list(g.values())


def score(nets, **kw):
    inc = fin = pure = grouped = 0
    pair_all = pair_together = 0
    for events in nets:
        gs = groups(events, **kw)
        member = {}
        for gi, g in enumerate(gs):
            for i in g:
                member[i] = gi
            if len(g) < 2:
                continue
            c = collections.Counter(events[i]["label"] for i in g)
            none = c.pop(None, 0)
            best = max(max(c.values(), default=0), 1 if none else 0)
            inc += 1
            fin += len(g)
            pure += best
        by_label = collections.defaultdict(list)
        for i, e in enumerate(events):
            if e["label"] is not None:
                by_label[e["label"]].append(i)
        for idx in by_label.values():
            if len(idx) > 400:
                idx = idx[:400]
            for a, b in itertools.combinations(idx, 2):
                pair_all += 1
                pair_together += member[a] == member[b]
        grouped += sum(len(g) for g in gs if len(g) >= 2)
    total = sum(len(e) for e in nets)
    return {"inc": inc, "per_inc": round(fin / max(inc, 1), 2), "purity": round(pure / max(fin, 1), 3),
            "grouped": round(grouped / max(total, 1), 3), "recall_pairs": round(pair_together / max(pair_all, 1), 3)}


def main():
    nets = []
    for line in open(sys.argv[1], encoding="utf-8"):
        line = line.strip()
        if line:
            nets.append(json.loads(line)["events"])
    print("sítí", len(nets), "událostí", sum(map(len, nets)),
          "s pravdou", sum(e["label"] is not None for n in nets for e in n))
    for gap in (6 * 3600, 3600, 1800, 900, 300):
        print("base gap", gap, score(nets, gap=gap))
    for gap in (3600, 1800, 900):
        for hub in (3, 5, 10, 20, 50):
            print("hub", hub, "gap", gap, score(nets, gap=gap, hub=hub))
        print("same_kind gap", gap, score(nets, gap=gap, same_kind=True))
        for hub in (10, 50):
            print("same_kind+hub", hub, "gap", gap, score(nets, gap=gap, hub=hub, same_kind=True))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
