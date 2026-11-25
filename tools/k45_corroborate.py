#!/usr/bin/env python3
"""Krok 45 (prototyp, offline): potvrzení slabé vazby druhým nezávislým zdrojem (PicoDomain).

Nálezy se spojí, když sdílejí adresu (jako B1b) A ZÁROVEŇ je jejich spojení potvrzeno druhým
zdrojem: (a) NTLM/SMB autentizace mezi jejich hosty v okně, nebo (b) oba hosty komunikují se
vzácným vnějším cílem (cíl, se kterým za celý záznam komunikovalo ≤ 2 vnitřní hosty),
nebo (c) silná vazba (stejný host a protějšek). Srovnání se samotným B1b a s B1.
Neprodukční kód: měří, zda má cenu psát korelační vrstvu o druhém zdroji.
"""
import glob
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
k39 = load("k39_pico")
SCOPE = "10.99.99."


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def jl(pattern):
    for path in sorted(glob.glob(pattern)):
        for line in open(path, encoding="utf-8", errors="replace"):
            try:
                yield json.loads(line)
            except ValueError:
                pass


def main():
    zeek, run, red = sys.argv[1], sys.argv[2], sys.argv[3]
    res = json.load(open(os.path.join(run, "result.json"), encoding="utf-8"))
    ntlm = defaultdict(list)  # (a,b) -> [t]
    for r in jl(os.path.join(zeek, "*", "ntlm.*.log")):
        if r.get("success"):
            a, b = r["id.orig_h"], r["id.resp_h"]
            ntlm[frozenset((a, b))].append(ts(r["ts"]))
    ext_hosts = defaultdict(set)  # vnější cíl -> vnitřní hosti
    for r in jl(os.path.join(zeek, "*", "conn.*.log")):
        a, b = r["id.orig_h"], r["id.resp_h"]
        if a.startswith(SCOPE) and not b.startswith(SCOPE):
            ext_hosts[b].add(a)
    rare = {d for d, hs in ext_hosts.items() if len(hs) <= 2}
    ext_of = defaultdict(set)  # host -> vzácné vnější cíle
    for d in rare:
        for h in ext_hosts[d]:
            ext_of[h].add(d)
    shown = res["shown"]
    host_of = {}
    for f in shown:
        ips = [x for x in k33.ips_of(f["text"]) if x.startswith(SCOPE)]
        host_of[f["id"]] = ips
    window = 1800

    def corroborated(a, b):
        ha, hb = set(host_of[a["id"]]), set(host_of[b["id"]])
        if ha & hb:
            return "strong"
        for x in ha:
            for y in hb:
                if any(abs(t - a["t"]) <= window or abs(t - b["t"]) <= window for t in ntlm.get(frozenset((x, y)), [])):
                    return "ntlm"
                if ext_of.get(x, set()) & ext_of.get(y, set()):
                    return "rare_ext"
        return None
    # B1b hrany, potvrzené druhým zdrojem
    order = sorted(range(len(shown)), key=lambda i: shown[i]["t"])
    parent = list(range(len(shown)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    last, kinds = {}, defaultdict(int)
    for i in order:
        for ip in k33.ips_of(shown[i]["text"]):
            if ip in last:
                j = last[ip]
                if shown[i]["t"] - shown[j]["t"] <= 6 * 3600:
                    c = corroborated(shown[i], shown[j])
                    if c:
                        parent[find(i)] = find(j)
                        kinds[c] += 1
            last[ip] = i
    groups = defaultdict(list)
    for i in range(len(shown)):
        groups[find(i)].append(shown[i]["id"])
    arms = {"B1": k33.groups_ip(shown), "B1b": k39.k35.groups_ip_window(shown),
            "corroborated": list(groups.values())}
    ips, events = k39.red_truth(red)
    camp = {e["ip"] for e in events} | {k39.C2}
    t_lo = min(e["t"] for e in events) - window
    t_hi = max(e["t"] for e in events) + window
    chain = {f["id"] for f in shown if k33.ips_of(f["text"]) & camp and t_lo <= f["t"] <= t_hi}
    out = {"edges_by_corroboration": dict(kinds), "chain_findings": len(chain), "shown": len(shown)}
    for name, g in arms.items():
        g = [x for x in g if len(x) >= 2]
        ci = [x for x in g if any(f in chain for f in x)]
        tot = sum(len(x) for x in ci)
        non = sum(1 for x in ci for f in x if f not in chain)
        out[name] = {"incidents": len(g), "chain_incidents": len(ci),
                     "completeness": round(max((sum(1 for f in x if f in chain) for x in ci), default=0) / len(chain), 2) if chain else 0,
                     "contamination": round(non / tot, 2) if tot else 0,
                     "largest": max((len(x) for x in g), default=0)}
    print(json.dumps(out, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
