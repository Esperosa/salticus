#!/usr/bin/env python3
"""Krok 17, laboratoř B: DNS tunel (iodine, dnscat2), DoH a kontrola (impl-krok17.md).

Spustí `labs/k17/composeb.yml` (resolver, autorita, web, iodine a dnscat2 server, DoH),
pak pro každou relaci spustí klientský kontejner, který si sám zachytí pcap do
`<out>/pcapb/<label>.pcap`, počká a kontejner zastaví. Vše jen uvnitř sítě 10.88.0.0/16.

Pouziti:
  python -I tools/k17_labb.py --set debug --out F:/Projekty/bakula-datasets/lab-k17/debugB
"""
import argparse
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, "labs", "k17")
P = "k17b"
NET = f"{P}_labb"
SETS = {"debug": {"iodine": 1, "dnscat": 1, "doh": 1, "control": 1},
        "held": {"iodine": 2, "dnscat": 2, "doh": 2, "control": 2}}


def sh(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd[:4]}: {r.stderr[-400:]}")
    return r


def compose(*args):
    return sh(["docker", "compose", "-p", P, "-f", os.path.join(LAB, "composeb.yml")] + list(args), check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True, choices=sorted(SETS))
    ap.add_argument("--out", required=True)
    ap.add_argument("--warmup", type=int, default=25)
    ap.add_argument("--dur", type=int, default=170, help="délka relace v s")
    args = ap.parse_args()
    os.makedirs(os.path.join(args.out, "pcapb"), exist_ok=True)
    os.environ["LOGDIR"] = os.path.abspath(args.out)
    labels = open(os.path.join(args.out, "labels.jsonl"), "a", encoding="utf-8")
    compose("down", "-t", "3")
    compose("up", "-d")
    time.sleep(args.warmup)
    try:
        i = 0
        for mode, count in SETS[args.set].items():
            for rep in range(count):
                label = f"{mode}-{rep}"
                name = f"{P}-cli-{label}"
                sh(["docker", "rm", "-f", name])
                run = ["docker", "run", "-d", "--name", name, "--network", NET, "--cap-add", "NET_ADMIN",
                       "--cap-add", "NET_RAW", "-e", f"ROUNDS=1", "-v", f"{os.path.join(LAB, 'rolesb')}:/lab:ro",
                       "-v", f"{os.path.abspath(args.out)}:/out", "k17labb:1", "sh", "/lab/tunnel_client.sh", mode, label]
                t0 = time.time()
                r = sh(run)
                if r.returncode != 0:
                    labels.write(json.dumps({"relation": label, "mode": mode, "error": r.stderr[-300:]}) + "\n")
                    labels.flush()
                    continue
                time.sleep(args.dur)
                sh(["docker", "stop", "-t", "8", name])
                logs = sh(["docker", "logs", name]).stdout[-400:]
                sh(["docker", "rm", "-f", name])
                labels.write(json.dumps({"relation": label, "mode": mode, "start": t0, "end": time.time(),
                                         "pcap": f"pcapb/{label}.pcap"}) + "\n")
                labels.flush()
                print(f"{i} {label} hotovo", flush=True)
                i += 1
    finally:
        compose("down", "-t", "5")
        for mode, count in SETS[args.set].items():
            for rep in range(count):
                sh(["docker", "rm", "-f", f"{P}-cli-{mode}-{rep}"])


if __name__ == "__main__":
    main()
