#!/usr/bin/env python3
"""Krok 32: prověření pravidla „opakované neúspěšné pokusy na stejný vnější cíl“ bez produktu.
Práh předem: >= N neúspěšných TCP pokusů (S0, REJ, RSTOS0) vnitřního hosta na stejný (cíl, port)
během T sekund a žádné úspěšné spojení na tento (cíl, port) v tomtéž úseku."""
import collections, ipaddress, sys

N, T = 20, 600


def probe(flows, scope, n=N, span=T):
    net = ipaddress.ip_network(scope)
    by = collections.defaultdict(list)  # (src,dst,port) -> [(ts, failed)]
    for ts, s, d, dp, failed in flows:
        try:
            if ipaddress.ip_address(s) in net and ipaddress.ip_address(d) not in net:
                by[(s, d, dp)].append((ts, failed))
        except ValueError:
            pass
    out = {}
    for key, v in by.items():
        v.sort()
        if sum(1 for x in v if x[1]) < n:
            continue
        j = 0
        fails = ok = 0
        for i, (t, f) in enumerate(v):
            if f:
                fails += 1
            else:
                ok += 1
            while t - v[j][0] > span:
                if v[j][1]:
                    fails -= 1
                else:
                    ok -= 1
                j += 1
            if fails >= n and ok == 0:
                out[key] = max(out.get(key, 0), fails)
    return out


if __name__ == "__main__":
    flows = []
    for l in open(sys.argv[1], encoding="utf-8", errors="replace"):
        if l.startswith("#"):
            continue
        p = l.rstrip("\n").split("\t")
        if len(p) > 11 and p[6] == "tcp":
            flows.append((float(p[0]), p[2], p[4], p[5], p[11] in ("S0", "REJ", "RSTOS0")))
    hits = probe(flows, sys.argv[2])
    print(len(hits), sorted(hits.items(), key=lambda x: -x[1])[:15])
