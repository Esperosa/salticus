#!/usr/bin/env python3
"""Vyhodnocení kroku 32 podle docs/diplomka/eval/predreg-krok32.md."""
import json, sys

K31 = "F:/work-tmp/shadow/k31"
K32 = "F:/work-tmp/shadow/k32"
NEW = [23, 7, 10]
IOT = ["CTU-IoT-Malware-Capture-20-1", "CTU-IoT-Malware-Capture-21-1", "CTU-IoT-Malware-Capture-3-1",
       "CTU-IoT-Malware-Capture-34-1", "CTU-IoT-Malware-Capture-42-1", "CTU-IoT-Malware-Capture-44-1",
       "CTU-IoT-Malware-Capture-8-1", "CTU-Honeypot-Capture-4-1", "CTU-Honeypot-Capture-5-1",
       "CTU-Honeypot-Capture-7-1-Somfy-01"]
CTU = [43, 44, 45, 46, 47, 48, 49, 50, 52, 53]


def load(d, n):
    try:
        return json.load(open(f"{d}/{n}.json", encoding="utf-8"))
    except FileNotFoundError:
        return None


def got(r):
    return sum(1 for h in r["hosts"].values() if h["credited"])


print("ČÁST A: nové nezávislé scénáře, outbound_scan (C) proti výchozímu (A)")
print(f"{'scénář':10}{'infik.':>7}{'A':>5}{'C':>5}{'zobr. A':>10}{'zobr. C':>10}{'scan':>7}   infikovaní zachycení v C: hosté")
tot = [0, 0, 0, 0]
loss = 0
for n in NEW:
    a, c = load(K32, f"new{n}_A"), load(K32, f"new{n}_C")
    if not a or not c:
        print(n, "chybí")
        continue
    ga, gc = got(a), got(c)
    tot[0] += ga; tot[1] += gc; tot[2] += a["displayed_total"]; tot[3] += c["displayed_total"]
    loss += gc < ga
    det = {ip: ("A" if h["credited"] else "-") for ip, h in a["hosts"].items()}
    detc = {ip: ("C" if h["credited"] else "-") for ip, h in c["hosts"].items()}
    print(f"{n:<10}{a['infected']:>7}{ga:>5}{gc:>5}{a['displayed_total']:>10}{c['displayed_total']:>10}"
          f"{c['types'].get('outbound_scan', 0):>7}   A:{det} C:{detc}")
print(f"H-A1 (C<A): {loss} scénářů -> {'SPLNĚNO' if loss == 0 else 'NESPLNĚNO'}")
print(f"H-A2 (C zachytí o ≥1 host víc): {tot[1] - tot[0]} -> {'SPLNĚNO' if tot[1] - tot[0] >= 1 else 'NESPLNĚNO'}")
print(f"H-A3 (zobrazeno C/A ≤ 1,5): {tot[3] / max(1, tot[2]):.3f} -> {'SPLNĚNO' if tot[3] <= 1.5 * tot[2] else 'NESPLNĚNO'}")

print("\nČÁST B: unanswered_retry (D) proti výchozímu (A)")
rows = []
for n in NEW:
    rows.append((f"nový {n}", load(K32, f"new{n}_A"), load(K32, f"new{n}_D")))
for d in IOT:
    rows.append((d, load(K31, f"iot_{d}_A"), load(K32, f"iot_{d}_D")))
for s in CTU:
    rows.append((f"CTU-13 {s}", load(K31, f"ctu_{s}_A"), load(K32, f"ctu_{s}_D")))
tb = [0, 0, 0, 0]
lossb = 0
for name, a, d in rows:
    if not a or not d:
        print(f"{name:36} chybí")
        continue
    ga, gd = got(a), got(d)
    tb[0] += ga; tb[1] += gd; tb[2] += a["displayed_total"]; tb[3] += d["displayed_total"]
    lossb += gd < ga
    r = d["types"].get("unanswered_retry", 0)
    print(f"{name:36}{a['infected']:>5}{ga:>4}{gd:>4}{a['displayed_total']:>9}{d['displayed_total']:>9}{r:>6}")
home_a, home_d = load(K31, "home_A"), load(K32, "home_D")
hr = home_d["types"].get("unanswered_retry", 0) if home_d else None
print(f"H-B1 (D<A): {lossb} scénářů -> {'SPLNĚNO' if lossb == 0 else 'NESPLNĚNO'}")
ratio = tb[3] / max(1, tb[2])
print(f"H-B2 (zobrazeno D/A): {ratio:.3f}; domácí síť unanswered_retry: {hr} -> "
      f"{'SPLNĚNO' if ratio <= 1.25 and hr is not None and hr <= 3 else 'NESPLNĚNO'}")
print(f"H-B3 (infikovaných navíc): {tb[1] - tb[0]}")
if home_d:
    print("domácí síť, hostů s retry:", home_d.get("outbound_scan_hosts"), "typy:", {k: v for k, v in home_d["types"].items() if k in ("unanswered_retry",)})
