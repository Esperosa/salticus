#!/usr/bin/env python3
"""Krok 22, laboratoř C: plán úloh, kalendář kontextu a útoky se štítky (impl-krok22.md, 5.3).

Spustí `labs/k22/compose.yml`, **před první úlohou** zapíše `context-calendar.json` z plánu slotů
(ne z výsledků) a projde sloty (normál, úloha nebo úloha s útokem, po) v pořadí daném semínkem.
Štítky zapisuje do `<out>/labels.jsonl`. Vše jen uvnitř 10.77.0.0/16; nic se neposílá ven.

Pouziti:
  python -I tools/k22_lab.py --seed 22001 --out F:/Projekty/bakula-datasets/lab-k22/22001
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, "labs", "k22")
P = "k22c"
IP = {"c1": "10.77.1.11", "c2": "10.77.1.12", "backup": "10.77.1.20", "scanner": "10.77.1.30",
      "batch": "10.77.1.40", "web": "10.77.2.10", "fs": "10.77.2.20", "app": "10.77.2.30",
      "sink": "10.77.9.9", "ext": "10.77.9.10"}
SLOTS = ["BK1", "BK2", "BK3", "BKN", "BA1", "BA2", "SC1", "SC2", "SA1", "SA2", "SA3", "BB1", "BB2", "BB3",
         "SD1"]
OWNER = "lab-operator"
SCOPE = ["10.77.2.0/24", IP["ext"]]
MARGIN = 30
PHASE = 120


def sh(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stderr[-500:]}")
    return r


def dx(svc, script):
    return sh(["docker", "exec", "-d", f"{P}-{svc}-1", "sh", "-c", script])


def compose(*args):
    return sh(["docker", "compose", "-p", P, "-f", os.path.join(LAB, "compose.yml")] + list(args), check=True)


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


def job(sid):
    """(druh kontextu nebo None, záznam v kalendáři, úlohy [(kontejner, příkaz)], útoky [(štítek, kontejner, příkaz)])."""
    t = PHASE - 5
    backup = ("backup", f"timeout {t} python3 /lab/node.py backup {IP['fs']} {IP['app']}")
    scan = ("scanner", f"timeout {t} nmap -sV -T4 -n -Pn --max-retries 1 -p 22,80,443,445,5432 "
                       f"10.77.2.0/24 {IP['ext']} >/dev/null 2>&1")
    batch = ("batch", f"timeout {t} python3 /lab/node.py batch")
    a = ("A", "c1", f"timeout {t} nmap -sS -T4 -n -Pn --max-retries 1 -p 1-1024 10.77.2.0/24 >/dev/null 2>&1")
    c = ("C", "scanner", f"timeout {t} nmap -sS -T4 -n -Pn --max-retries 1 -p 1-1024 {IP['sink']} >/dev/null 2>&1")
    b = ("B", "backup", f"timeout {t} python3 /lab/node.py exfil 30")
    d = ("D", "scanner", f"timeout {t} nmap -sS -T4 -n -Pn --max-retries 1 -p- "
                         f"{IP['web']} {IP['fs']} {IP['app']} >/dev/null 2>&1")
    if sid.startswith("BK"):
        return "backup", sid != "BKN", [backup], []
    if sid.startswith("BA"):
        return "batch_job", True, [batch], []
    if sid.startswith("SC"):
        return "authorized_scanner", True, [scan], []
    if sid.startswith("SA"):
        return "authorized_scanner", True, [scan], [a, c]
    if sid.startswith("BB"):
        return "backup", True, [backup], [b]
    if sid == "SD1":
        return "authorized_scanner", True, [scan], [d]
    raise ValueError(sid)


def entry(kind, start, end):
    hosts, sources = {
        "backup": ([IP["fs"], IP["app"]], [IP["backup"]]),
        "batch_job": ([IP["fs"]], [IP["batch"]]),
        "authorized_scanner": (SCOPE, [IP["scanner"]]),
    }[kind]
    return {"kind": kind, "hosts": hosts, "sources": sources, "start": iso(start - MARGIN),
            "end": iso(end + MARGIN), "covers": [], "approved_by": OWNER,
            "expires": iso(end + MARGIN + 86400)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--warmup", type=int, default=300)
    ap.add_argument("--phase", type=int, default=120)
    ap.add_argument("--only", default="", help="ladeni skriptu: jen vyjmenovane sloty (carkou)")
    args = ap.parse_args()
    global PHASE
    PHASE = args.phase
    os.makedirs(args.out, exist_ok=True)
    os.environ["LOGDIR"] = os.path.abspath(args.out)
    rnd = random.Random(args.seed)
    order = SLOTS[:]
    rnd.shuffle(order)
    if args.only:
        order = args.only.split(",")
    sh(["docker", "compose", "-p", P, "-f", os.path.join(LAB, "compose.yml"), "down", "-t", "2"])
    compose("up", "-d")
    t0 = time.time()
    # plan slotu a kalendar PRED prvni ulohou (z planu, ne z vysledku)
    plan, calendar = [], []
    for n, sid in enumerate(order):
        start = t0 + args.warmup + n * 3 * PHASE
        kind, recorded, _, _ = job(sid)
        plan.append((n, sid, start, start + PHASE, start + 2 * PHASE, start + 3 * PHASE))
        if recorded:
            calendar.append(entry(kind, start + PHASE, start + 2 * PHASE))
    with open(os.path.join(args.out, "context-calendar.json"), "w", encoding="utf-8") as h:
        json.dump(calendar, h, indent=1)
    labels = open(os.path.join(args.out, "labels.jsonl"), "a", encoding="utf-8")

    def label(rec):
        labels.write(json.dumps(rec) + "\n")
        labels.flush()

    label({"slot": "warmup", "start": t0, "end": t0 + args.warmup, "seed": args.seed, "phase": PHASE,
           "calendar_written": time.time()})

    def until(ts):
        time.sleep(max(0.0, ts - time.time()))

    try:
        for n, sid, start, fs, fe, end in plan:
            kind, recorded, tasks, attacks = job(sid)
            until(fs)
            real_fs = time.time()
            for svc, cmd in tasks:
                dx(svc, cmd)
            for _, svc, cmd in attacks:
                dx(svc, cmd)
            until(fe)
            real_fe = time.time()
            until(end)
            label({"slot": n, "scenario": sid, "seed": args.seed, "start": start, "fault_start": real_fs,
                   "fault_end": real_fe, "end": time.time(), "kind": kind, "recorded": recorded,
                   "job_sources": {"backup": [IP["backup"]], "batch_job": [IP["batch"]],
                                   "authorized_scanner": [IP["scanner"]]}[kind],
                   "attacks": [{"label": lab, "source": IP[svc]} for lab, svc, _ in attacks]})
            print(f"{n} {sid} hotovo", flush=True)
    finally:
        time.sleep(5)
        sh(["docker", "compose", "-p", P, "-f", os.path.join(LAB, "compose.yml"), "down", "-t", "5"])


if __name__ == "__main__":
    sys.exit(main())
