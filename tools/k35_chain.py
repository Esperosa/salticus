#!/usr/bin/env python3
"""Krok 35: rozšířený generátor řetězců (varianty z kroku 33 plus rozvětvení a jedno okno).

Varianty: simple, pivot, collision (dvojice se sdíleným vnějším cílem a serverem), fanout
(útočník hrubou silou na tři oběti, jedna z nich posílá data ven) a samewin (sken, hrubá síla
a výstup dat během jednoho 30minutového okna). Pravda obsahuje `all_ips` (i sdílené adresy),
aby se dal oddělit čistý šum pozadí od nálezů, které patří řetězcům.

  k35_chain.py gen --conn conn.log --out zeek_dir --truth truth.json [--seed N] [--per 12]
"""
import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("k33_chain", os.path.join(HERE, "k33_chain.py"))
k33 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(k33)
inject = k33.inject


class Chains35(k33.Chains):
    def chain(self, cid, variant, t, shared=None):
        if variant not in ("fanout", "samewin"):
            super().chain(cid, variant, t, shared)
            rec = self.truth[-1]
            rec["all_ips"] = list(rec["ips"]) + [rec["ext"]] + ([shared["s"]] if shared else [])
            return
        a = self.ip()
        x = self.ext()
        phases = []

        def ph(n, kind, actor, peer, t0, t1):
            phases.append({"phase": n, "kind": kind, "actor": actor, "peer": peer, "t0": t0, "t1": t1})
        if variant == "fanout":
            v1, v2, v3 = self.ip(), self.ip(), self.ip()
            self.scan(t, a, v1)
            ph(1, "scan", a, v1, t, t + 100)
            for k, v in enumerate((v1, v2, v3)):
                self.brute(t + 900 + k * 40, a, v)
                ph(2, "brute", a, v, t + 900 + k * 40, t + 1500 + k * 40)
            self.exfil(t + 2400, v1, x)
            ph(3, "exfil", v1, x, t + 2400, t + 3000)
            ips = [a, v1, v2, v3]
        else:  # samewin: vše v 30 minutách od začátku okna
            v = self.ip()
            self.scan(t, a, v)
            ph(1, "scan", a, v, t, t + 100)
            self.brute(t + 200, a, v)
            ph(2, "brute", a, v, t + 200, t + 800)
            self.exfil(t + 900, v, x)
            ph(3, "exfil", v, x, t + 900, t + 1500)
            ips = [a, v]
        self.truth.append({"chain": cid, "variant": variant, "t": t, "ips": ips, "ext": x,
                           "shared": False, "phases": phases, "all_ips": ips + [x]})


def first_ts(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            if not raw.startswith("#"):
                return float(raw.split("	")[0])
    raise SystemExit("prazdny zaznam")


def cmd_gen(a):
    used = inject.used_ips(a.conn)
    rec_t0 = first_ts(a.conn)
    g = Chains35(a.seed, used)
    plan, cid = [], 0
    for variant in ("simple", "pivot", "fanout", "samewin", "collision"):
        for _ in range(a.per if variant != "collision" else a.per // 2):
            plan.append((variant, cid))
            cid += 2 if variant == "collision" else 1
    g.rng.shuffle(plan)
    slot = 0
    for variant, c in plan:
        t = inject.T0 + 3600 + slot * k33.SLOT + g.rng.random() * 300
        if variant == "samewin":
            # začátek 30minutového okna přehrání (okna se počítají od prvního toku záznamu)
            t = rec_t0 + int((t - rec_t0) // 1800) * 1800 + 30
        slot += 1
        if variant == "collision":
            shared = {"x": g.ext(), "s": g.ip()}
            g.chain(c, "collision", t, shared)
            g.chain(c + 1, "collision", t + 300, shared)
        else:
            g.chain(c, variant, t)
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
    g.add_argument("--seed", type=int, default=35)
    g.add_argument("--per", type=int, default=12)
    a = ap.parse_args()
    if a.cmd == "gen":
        cmd_gen(a)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
