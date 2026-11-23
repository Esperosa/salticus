#!/usr/bin/env python3
"""Vyhodnocení kroku 31 podle docs/diplomka/eval/predreg-krok31.md."""
import glob, json, math, os, sys

DIR = sys.argv[1] if len(sys.argv) > 1 else "F:/work-tmp/shadow/k31"
IOT = ["CTU-IoT-Malware-Capture-20-1", "CTU-IoT-Malware-Capture-21-1", "CTU-IoT-Malware-Capture-3-1",
       "CTU-IoT-Malware-Capture-34-1", "CTU-IoT-Malware-Capture-42-1", "CTU-IoT-Malware-Capture-44-1",
       "CTU-IoT-Malware-Capture-8-1"]
HONEY = ["CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1", "CTU-Honeypot-Capture-7-1-Somfy-01"]
CTU = [43, 44, 45, 46, 47, 48, 49, 50, 52, 53]


def load(name):
    try:
        return json.load(open(f"{DIR}/{name}.json", encoding="utf-8"))
    except FileNotFoundError:
        return None


def got(r):
    return sum(1 for h in r["hosts"].values() if h["credited"])


def row(label, a, c):
    if a is None or c is None:
        print(f"{label:34} chybí")
        return None
    ga, gc = got(a), got(c)
    print(f"{label:34}{a['infected']:>6}{ga:>8}{gc:>8}{a['displayed_total']:>9}{c['displayed_total']:>9}"
          f"{c['types'].get('outbound_scan', 0):>8}")
    return (ga, gc, a["displayed_total"], c["displayed_total"], a["infected"])


print(f"{'scénář':34}{'infik.':>6}{'A zach.':>8}{'C zach.':>8}{'A zobr.':>9}{'C zobr.':>9}{'scan':>8}")
groups = {"IoT-23": [], "honeypot": [], "CTU-13": []}
for d in IOT:
    r = row(d, load(f"iot_{d}_A"), load(f"iot_{d}_C"))
    r and groups["IoT-23"].append(r)
for d in HONEY:
    r = row(d, load(f"iot_{d}_A"), load(f"iot_{d}_C"))
    r and groups["honeypot"].append(r)
for s in CTU:
    r = row(f"CTU-13 Botnet-{s}", load(f"ctu_{s}_A"), load(f"ctu_{s}_C"))
    r and groups["CTU-13"].append(r)
print()
allr = [x for g in groups.values() for x in g]
for name, g in groups.items():
    if g:
        print(f"{name:10}: A {sum(x[0] for x in g)}, C {sum(x[1] for x in g)} z {sum(x[4] for x in g)} infikovaných; "
              f"zobrazeno A {sum(x[2] for x in g)}, C {sum(x[3] for x in g)}")
loss = sum(1 for x in allr if x[1] < x[0])
gain_h = sum(x[1] - x[0] for x in allr)
ratio = sum(x[3] for x in allr) / max(1, sum(x[2] for x in allr))
home = load("home_C")
scan_home = home["types"].get("outbound_scan", 0) if home else None
print(f"\nH1 (C < A ve scénářích): {loss} z {len(allr)} -> {'SPLNĚNO' if loss == 0 else 'NESPLNĚNO'}")
print(f"H2 (zobrazeno C/A přes scénáře): {ratio:.3f}; domácí síť outbound_scan zobrazeno: {scan_home} "
      f"-> {'SPLNĚNO' if ratio <= 1.25 and scan_home is not None and scan_home <= 3 else 'NESPLNĚNO'}")
iot_gain = sum(x[1] - x[0] for x in groups["IoT-23"])
ctu_gain = sum(x[1] - x[0] for x in groups["CTU-13"])
print(f"H3 (přínos, hostů navíc): IoT-23 {iot_gain}, CTU-13 {ctu_gain}, celkem {gain_h} (hranice 3)")
if home:
    print("domácí síť, hostů s outbound_scan:", home["outbound_scan_hosts"])
