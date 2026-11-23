#!/usr/bin/env python3
"""Krok 25: hranice detekce na reálném pozadí (útoky vložené do skutečného conn.log).

Podmínky měření (poctivě):
- pozadí je skutečný conn.log z domácí sítě (beze změny), útoky jsou syntetické a vložené po něm;
- každý epizodní útočník má vlastní IP, takže detekce se přiřazuje jednoznačně;
- cíle jsou adresy v rozsahu, které v záznamu nikdy nebyly (neznámé zařízení). Útoky na hosty
  z aktivního inventáře se touto metodou přiřadit nedají (události se spojí s hostem a ztratí
  zdrojovou IP), proto se neměří;
- šest rodin je skutečný útok (měří se zachycení), tři rodiny jsou pokusy o schování pod
  známou činnost (měří se, kolik toků modul skryje).

Použití:
  k25_inject.py gen  --conn zeek/logs/conn.log --out zeek_bench --truth truth.json [--seed N]
  k25_inject.py eval --report report.json --truth truth.json
"""
import argparse
import datetime as dt
import json
import math
import random
import sys

FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes "
          "resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts "
          "orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents ip_proto").split()
EPISODES_PER_FAMILY = 10
# čas pozadí: 21.–22. 11. 2026 (mimo okno deklarovaného vlastního skenu 20. 11.)
T0 = dt.datetime(2026, 11, 21, 6, 0, 0, tzinfo=dt.timezone.utc).timestamp()


def line(ts, uid, src, sport, dst, dport, proto, dur, ob, rb, state, hist, op, oib, rp, rib):
    def f(v):
        return "-" if v is None else (f"{v:.6f}" if isinstance(v, float) else str(v))
    row = [f"{ts:.6f}", uid, src, sport, dst, dport, proto, "-", f(dur), f(ob), f(rb), state,
           "T", "T", "0", hist, op, oib, rp, rib, "-", "6" if proto == "tcp" else "17"]
    return "\t".join(str(x) for x in row)


class Gen:
    def __init__(self, seed, used):
        self.rng = random.Random(seed)
        self.wrng = random.Random(seed + 1)  # zahřívací provoz nesmí posunout adresy epizod
        self.n = 0
        self.free = [f"192.168.1.{i}" for i in range(2, 255) if f"192.168.1.{i}" not in used]
        self.rng.shuffle(self.free)
        # sdílená sada cílů pro horizontální sken (adres v /24 je málo)
        self.pool = [self.free.pop() for _ in range(40)]
        self.lines = []
        self.truth = []

    def ip(self):
        return self.free.pop()

    def uid(self):
        self.n += 1
        return f"Cbench{self.n:08d}"

    def start(self, k):
        # epizody rozložené po 21.–22. 11.
        return T0 + (k * 3 + self.rng.random()) * 1800

    def syn(self, ts, src, dst, dport, state="S0"):
        self.lines.append(line(ts, self.uid(), src, self.rng.randint(32768, 60999), dst, dport,
                               "tcp", None, None, None, state, "S", 1, 60, 0, 0))

    def episode(self, family, k, kind, src, dst, t=None):
        self.truth.append({"family": family, "episode": k, "kind": kind, "src": src, "dst": dst,
                           "t": t})

    def warm(self, src, t_end, hours=4):
        """Ustálený provoz hosta před útokem: pravidelné spojení na tři pevné cíle (host není
        nový, jeho výchozí chování je znám; útok míří na NOVÝ cíl)."""
        for i in range(int(hours * 12)):
            for d in ("192.0.2.10", "192.0.2.11", "192.0.2.12"):
                self.lines.append(line(t_end - (i + 1) * 300 + self.wrng.random() * 5, self.uid(),
                                       src, self.wrng.randint(32768, 60999), d, 443, "tcp", 0.5,
                                       800, 5000, "SF", "ShADadFf", 9, 1200, 8, 5400))

    # --- skutečné útoky ---
    def vertical_scan(self, k):
        src, dst, t = self.ip(), self.ip(), self.start(k)
        for i, port in enumerate(self.rng.sample(range(1, 10000), 1000)):
            self.syn(t + i * 0.1, src, dst, port)
        self.episode("vertical_scan", k, "attack", src, dst, t=t)

    def horizontal_scan(self, k):
        src, t = self.ip(), self.start(k)
        dsts = list(self.pool)
        for i, d in enumerate(dsts):
            for rep in range(8):
                self.syn(t + i * 2 + rep * 0.3, src, d, 445)
        self.episode("horizontal_scan", k, "attack", src, dsts[0], t=t)

    def ssh_bruteforce(self, k):
        src, dst, t = self.ip(), self.ip(), self.start(k)
        for i in range(300):
            self.lines.append(line(t + i * 2, self.uid(), src, self.rng.randint(32768, 60999),
                                   dst, 22, "tcp", 0.8, 1200, 900, "SF", "ShADadFf", 14, 1800, 12, 1500))
        self.episode("ssh_bruteforce", k, "attack", src, dst, t=t)

    def exfil_volume(self, k):
        src, t = self.ip(), self.start(k)
        self.warm(src, t)
        dst = f"198.51.100.{self.rng.randint(2, 250)}"
        for i in range(20):
            self.lines.append(line(t + i * 30, self.uid(), src, self.rng.randint(32768, 60999),
                                   dst, 443, "tcp", 25.0, 15_000_000, 4000, "SF", "ShADadFf",
                                   11000, 15_500_000, 2000, 90000))
        self.episode("exfil_volume", k, "attack", src, dst, t=t)

    def exfil_large(self, k):
        # nad absolutní mezí detektoru bez historie (1 GB za okno)
        src, t = self.ip(), self.start(k)
        dst = f"198.51.100.{self.rng.randint(2, 250)}"
        for i in range(20):
            self.lines.append(line(t + i * 30, self.uid(), src, self.rng.randint(32768, 60999),
                                   dst, 443, "tcp", 120.0, 75_000_000, 4000, "SF", "ShADadFf",
                                   55000, 77_000_000, 2000, 90000))
        self.episode("exfil_large", k, "attack", src, dst, t=t)

    def beaconing(self, k):
        src, t = self.ip(), self.start(k)
        self.warm(src, t)
        dst = f"198.51.100.{self.rng.randint(2, 250)}"
        for i in range(180):
            self.lines.append(line(t + i * 60 + self.rng.random() * 2, self.uid(), src,
                                   self.rng.randint(32768, 60999), dst, 443, "tcp", 0.4, 600, 450,
                                   "SF", "ShADadFf", 8, 1000, 7, 900))
        self.episode("beaconing", k, "attack", src, dst, t=t)

    def syn_flood(self, k):
        src, dst, t = f"203.0.113.{self.rng.randint(2, 250)}", self.ip(), self.start(k)
        for i in range(20000):
            self.syn(t + i * 0.003, src, dst, 80)
        self.episode("syn_flood", k, "attack", src, dst, t=t)

    # --- pokusy o schování pod známou činnost ---
    def ssdp_masquerade(self, k):
        # útočník podvrhne dotaz oběti a pak jí posílá "odpovědi" z mnoha zdrojů
        victim, dst, t = self.ip(), self.ip(), self.start(k)
        src = self.ip()
        for i in range(30):
            self.lines.append(line(t + i, self.uid(), victim, 50000, "239.255.255.250", 1900, "udp",
                                   None, None, None, "S0", "D", 1, 130, 0, 0))
        for i in range(600):
            self.lines.append(line(t + 40 + i * 0.5, self.uid(), src, 40000 + i % 100, victim, 50000,
                                   "udp", None, None, None, "S0", "D", 1, 300, 0, 0))
        self.episode("ssdp_masquerade", k, "evasion", src, victim, t=t)

    def broadcast_masquerade(self, k):
        src, t = self.ip(), self.start(k)
        for i in range(5000):
            self.lines.append(line(t + i * 0.5, self.uid(), src, 40000, "192.168.1.255", 137, "udp",
                                   None, None, None, "S0", "D", 1, 128, 0, 0))
        self.episode("broadcast_masquerade", k, "evasion", src, "192.168.1.255", t=t)

    def scanner_spoof(self, k):
        # podvržená IP deklarovaného skeneru (192.168.1.133) v jeho okně; jen jeden 'k' = 1 epizoda
        t = dt.datetime(2026, 11, 20, 10, 0, 0, tzinfo=dt.timezone.utc).timestamp() + k * 600
        dst = self.ip()
        for i, port in enumerate(self.rng.sample(range(1, 10000), 500)):
            self.syn(t + i * 0.2, "192.168.1.133", dst, port)
        self.episode("scanner_spoof", k, "evasion", "192.168.1.133", dst, t=t)


FAMILIES = ["vertical_scan", "horizontal_scan", "ssh_bruteforce", "exfil_volume", "exfil_large", "beaconing",
            "syn_flood", "ssdp_masquerade", "broadcast_masquerade", "scanner_spoof"]


def used_ips(path):
    used = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if raw.startswith("#"):
                continue
            p = raw.split("\t")
            if len(p) > 5:
                used.add(p[2])
                used.add(p[4])
    return used


def cmd_gen(a):
    used = used_ips(a.conn)
    g = Gen(a.seed, used)
    for fam in FAMILIES:
        for k in range(EPISODES_PER_FAMILY):
            getattr(g, fam)(k)
    import os
    os.makedirs(a.out, exist_ok=True)
    with open(a.conn, encoding="utf-8", errors="replace") as src, \
            open(os.path.join(a.out, "conn.log"), "w", encoding="utf-8", newline="\n") as out:
        for raw in src:
            if raw.startswith("#close"):
                continue
            out.write(raw)
        for ln in g.lines:
            out.write(ln + "\n")
        out.write("#close\t2026-11-23-07-19-24\n")
    json.dump(g.truth, open(a.truth, "w", encoding="utf-8"), indent=1)
    print(f"vlozeno {len(g.lines)} toku, {len(g.truth)} epizod")


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def cmd_eval(a):
    rep = json.load(open(a.report, encoding="utf-8"))
    truth = json.load(open(a.truth, encoding="utf-8"))
    # 'upozorneni' = jakákoli událost jiná než pouhý neočekávaný provoz a souhrn vysvětleného;
    # 'cokoli' = i neočekávaný provoz (nízká závažnost, bez významu pro útok)
    alert_src, alert_dst, any_src, any_dst, hidden = {}, {}, set(), set(), {}
    for u in rep["unmappedEvents"]:
        e = u["event"]
        if e["event_type"] == "explained_activity":
            hidden[e["src_ip"]] = hidden.get(e["src_ip"], 0) + e.get("count", 0)
            continue
        any_src.add(e["src_ip"])
        any_dst.add(e["dst_ip"])
        if e["event_type"] != "unexpected_traffic":
            alert_src[e["src_ip"]] = alert_src.get(e["src_ip"], 0) + 1
            alert_dst[e["dst_ip"]] = alert_dst.get(e["dst_ip"], 0) + 1
    # nálezy chování (v3) nesou útočníka v host_key a v evidenci, ne jako událost bez inventáře
    import re
    for fnd in rep.get("findings", []):
        if fnd.get("finding_type") in ("unexpected_traffic", "unmapped_passive_event"):
            continue
        text = " ".join([str(fnd.get("host_key", "")), str(fnd.get("service_key", ""))]
                        + [str(x) for x in fnd.get("evidence", [])])
        for ip in set(re.findall(r"\d+\.\d+\.\d+\.\d+", text)):
            alert_src[ip] = alert_src.get(ip, 0) + 1
            alert_dst[ip] = alert_dst.get(ip, 0) + 1
    by = {}
    for t in truth:
        by.setdefault(t["family"], []).append(t)
    print(f"{'rodina':22} {'druh':8} {'upozorneni':>11} {'95% interval':>14}  {'cokoli':>7}  skryto toku")
    for fam in FAMILIES:
        eps = by.get(fam, [])
        # podvržená IP skeneru se přiřazuje jen podle cíle (zdroj má i skutečné události);
        # horizontální sken má sdílené cíle, přiřazuje se jen podle zdroje
        use_src = fam != "scanner_spoof"
        # cíle exfiltrace a beaconingu jsou náhodné veřejné adresy, které se mohou opakovat
        use_dst = fam not in ("horizontal_scan", "exfil_volume", "exfil_large", "beaconing")

        def hit(t, srcs, dsts):
            return (use_src and srcs.get(t["src"], 0) > 0) or (use_dst and dsts.get(t["dst"], 0) > 0)
        n_alert = sum(1 for t in eps if hit(t, alert_src, alert_dst))
        n_any = sum(1 for t in eps if hit(t, {x: 1 for x in any_src}, {x: 1 for x in any_dst}))
        lo, hi = wilson(n_alert, len(eps))
        hid = "n/a" if fam == "scanner_spoof" else sum(hidden.get(t["src"], 0) for t in eps)
        print(f"{fam:22} {eps[0]['kind']:8} {n_alert:>6}/{len(eps):<4} [{lo:.2f},{hi:.2f}]  {n_any:>3}/{len(eps):<3}  {hid}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("--conn", required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--truth", required=True)
    g.add_argument("--seed", type=int, default=25)
    e = sub.add_parser("eval")
    e.add_argument("--report", required=True)
    e.add_argument("--truth", required=True)
    args = ap.parse_args()
    (cmd_gen if args.cmd == "gen" else cmd_eval)(args)
