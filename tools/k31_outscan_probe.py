#!/usr/bin/env python3
"""Krok 31: prověření pravidla odchozího skenování na označených datech (bez produktu).
Práh předem: >= 25 různých cílů bez odpovědi na stejném (host, port) za 300 s a podíl neúspěšných >= 0,5."""
import collections, csv, glob, ipaddress, sys
from datetime import datetime, timezone

K, SPAN, RATIO = 25, 300, 0.5


def probe(flows, scope):
    net = ipaddress.ip_network(scope)
    by = collections.defaultdict(list)
    for ts, s, d, dp, failed in flows:
        try:
            if ipaddress.ip_address(s) in net and ipaddress.ip_address(d) not in net:
                by[(s, dp)].append((ts, d, failed))
        except ValueError:
            pass
    hits = {}
    for key, v in by.items():
        v.sort()
        j = 0
        dst_fail = collections.Counter()
        total = fail = 0
        for i, (t, d, f) in enumerate(v):
            total += 1
            if f:
                fail += 1
                dst_fail[d] += 1
            while t - v[j][0] > SPAN:
                _, dj, fj = v[j]
                total -= 1
                if fj:
                    fail -= 1
                    dst_fail[dj] -= 1
                    if dst_fail[dj] == 0:
                        del dst_fail[dj]
                j += 1
            if len(dst_fail) >= K and fail / total >= RATIO:
                hits[key] = max(hits.get(key, 0), len(dst_fail))
    return hits


def load_binetflow(path):
    flows, infected = [], set()
    for r in csv.DictReader(open(path, encoding="utf-8", errors="replace", newline="")):
        if any(r.get(k) is None for k in ("StartTime", "Proto", "SrcAddr", "Dir", "DstAddr", "Dport", "Label", "State")):
            continue
        if r["Proto"].strip().lower() != "tcp":
            continue
        ts = datetime.strptime(r["StartTime"].strip(), "%Y/%m/%d %H:%M:%S.%f").replace(tzinfo=timezone.utc).timestamp()
        if "From-Botnet" in r["Label"]:
            infected.add(r["SrcAddr"].strip())
        # neúspěšné spojení: jen SYN, nebo SYN a odmítnutí (ne jednosměrný záznam s daty)
        failed = r["State"].strip() in ("S_", "SR_", "S_R", "S_RA", "SA_R")
        flows.append((ts, r["SrcAddr"].strip(), r["DstAddr"].strip(), r["Dport"].strip(), failed))
    return flows, infected


if __name__ == "__main__":
    for n in [int(x) for x in sys.argv[1:]]:
        f = glob.glob(f"labs/datasets/ctu13/Botnet-{n}/*.csv")[0]
        flows, inf = load_binetflow(f)
        hits = probe(flows, "147.32.84.0/24")
        hosts = {k[0] for k in hits}
        print(f"Botnet-{n}: infikovaní v rozsahu {sorted(h for h in inf if h.startswith('147.32.84.'))}, "
              f"hostů nad prahem {sorted(hosts)}; z toho neinfikovaných {sorted(hosts - inf)}")
