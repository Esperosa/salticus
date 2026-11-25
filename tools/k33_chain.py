#!/usr/bin/env python3
"""Krok 33: vícefázové vložené řetězce útoku s pravdou po řetězech (měření korelace).

Pozadí je skutečný conn.log z domácí sítě. Každý řetězec má unikátní IP účastníků (pravda se
přiřazuje podle IP), tři varianty:
  simple     A skenuje V, A hrubá síla na V:22, V posílá velký objem ven na X
  pivot      A skenuje V1, A hrubá síla na V1:22, V1 hrubá síla na V2:22, V2 posílá objem na X
  collision  dva souběžné řetězce typu simple, které sdílejí vnější cíl X a obětní server S
             (oba útočníci skenují i S); slouží k měření slévání nesouvisejících řetězců
Fáze jsou rozložené v čase (sken t, hrubá síla +900 s, výstup +2400 s), takže řetěz přesahuje
víc 30minutových oken a měří se i stav mezi okny.

Použití:
  k33_chain.py gen --conn zeek/logs/conn.log --out zeek_chain --truth truth_chain.json
                   [--seed N] [--chains 40]
Poznámka: generátor se po zmrazení nemění (hash commitu se zapisuje do predregistrace).
"""
import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("k25_inject", os.path.join(HERE, "k25_inject.py"))
inject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inject)

PHASE_GAP = (0, 900, 2400)
SLOT = 4200  # rozestup začátků řetězců (s); souběžné řetězce se překrývají jen v kolizi


class Chains(inject.Gen):
    def scan(self, t, src, dst):
        for i, port in enumerate(self.rng.sample(range(1, 10000), 1000)):
            self.syn(t + i * 0.1, src, dst, port)

    def brute(self, t, src, dst):
        for i in range(300):
            self.lines.append(inject.line(
                t + i * 2, self.uid(), src, self.rng.randint(32768, 60999), dst, 22, "tcp", 0.8,
                1200, 900, "SF", "ShADadFf", 14, 1800, 12, 1500))

    def exfil(self, t, src, dst):
        for i in range(20):
            self.lines.append(inject.line(
                t + i * 30, self.uid(), src, self.rng.randint(32768, 60999), dst, 443, "tcp", 120.0,
                75_000_000, 4000, "SF", "ShADadFf", 55000, 77_000_000, 2000, 90000))

    def ext(self):
        return f"198.51.100.{self.rng.randint(2, 250)}"

    def chain(self, cid, variant, t, shared=None):
        a, v = self.ip(), self.ip()
        x = shared["x"] if shared else self.ext()
        phases = []

        def ph(n, kind, actor, peer, t0, t1):
            phases.append({"phase": n, "kind": kind, "actor": actor, "peer": peer, "t0": t0,
                           "t1": t1})
        if variant == "pivot":
            v2 = self.ip()
            self.scan(t, a, v)
            ph(1, "scan", a, v, t, t + 100)
            self.brute(t + PHASE_GAP[1], a, v)
            ph(2, "brute", a, v, t + PHASE_GAP[1], t + PHASE_GAP[1] + 600)
            self.brute(t + 1500, v, v2)
            ph(3, "brute_lateral", v, v2, t + 1500, t + 2100)
            self.exfil(t + PHASE_GAP[2] + 600, v2, x)
            ph(4, "exfil", v2, x, t + PHASE_GAP[2] + 600, t + PHASE_GAP[2] + 1200)
            ips = [a, v, v2]
        else:
            self.scan(t, a, v)
            ph(1, "scan", a, v, t, t + 100)
            if shared:
                self.scan(t + 150, a, shared["s"])
                ph(1, "scan", a, shared["s"], t + 150, t + 250)
            self.brute(t + PHASE_GAP[1], a, v)
            ph(2, "brute", a, v, t + PHASE_GAP[1], t + PHASE_GAP[1] + 600)
            self.exfil(t + PHASE_GAP[2], v, x)
            ph(3, "exfil", v, x, t + PHASE_GAP[2], t + PHASE_GAP[2] + 600)
            ips = [a, v]
        self.truth.append({"chain": cid, "variant": variant, "t": t, "ips": ips, "ext": x,
                           "shared": bool(shared), "phases": phases})


def cmd_gen(a):
    used = inject.used_ips(a.conn)
    g = Chains(a.seed, used)
    # pořadí variant: třetina simple, třetina pivot, třetina kolizních dvojic
    n = a.chains
    slot = 0
    cid = 0
    plan = []
    while cid < n:
        for variant in ("simple", "pivot", "collision"):
            if cid >= n:
                break
            plan.append((variant, cid))
            cid += 2 if variant == "collision" else 1
    for variant, cid in plan:
        t = inject.T0 + 3600 + slot * SLOT + g.rng.random() * 300
        slot += 1
        if variant == "collision":
            shared = {"x": g.ext(), "s": g.ip()}
            g.chain(cid, "collision", t, shared)
            g.chain(cid + 1, "collision", t + 300, shared)
        else:
            g.chain(cid, variant, t)
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
    print(f"vlozeno {len(g.lines)} toku, {len(g.truth)} retezcu")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("--conn", required=True)
    g.add_argument("--out", required=True)
    g.add_argument("--truth", required=True)
    g.add_argument("--seed", type=int, default=33)
    g.add_argument("--chains", type=int, default=40)
    a = ap.parse_args()
    if a.cmd == "gen":
        cmd_gen(a)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
