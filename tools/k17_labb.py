#!/usr/bin/env python3
"""Krok 17, laboratoř B: DNS tunely, DoH a kontroly (impl-krok17.md, dodatek D1).

Spustí `labs/k17/composeb.yml` (resolver, autorita, weby, servery iodine, dnscat2, dns2tcp, DoH),
pak pro každou relaci spustí klientský kontejner, který si sám zachytí pcap do
`<out>/pcapb/<label>.pcap`, počká a kontejner zastaví. Vše jen uvnitř sítě 10.88.0.0/16.
Seed určuje pořadí relací a parametry klienta v předem daném rozsahu.

Pouziti:
  python -I tools/k17_labb.py --set debug --out F:/Projekty/bakula-datasets/lab-k17/debugB
  python -I tools/k17_labb.py --set debug --out ... --only dnscat-aaaa,control-av --dur 30   (zkouška)
"""
import argparse
import json
import os
import random
import subprocess
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, "labs", "k17")
P = "k17b"
NET = f"{P}_labb"
IMAGE = "k17labb:2"
TUNNELS = ["iodine", "iodine-txt", "iodine-cname", "iodine-mx", "iodine-a",
           "dnscat", "dnscat-txt", "dnscat-cname", "dnscat-mx", "dnscat-aaaa",
           "dns2tcp", "exfil-slow", "exfil-short", "exfil-multi"]
DOH = ["doh", "doh-keep"]
CONTROLS = ["control", "control-names", "control-av", "control-avburst", "control-mdns",
            "control-browse", "control-download", "control-stream", "control-poll", "control-pollkeep"]
ALL = TUNNELS + DOH + CONTROLS
SETS = {"debug": {"seed": 17001, "modes": ALL},
        "held": {"seed": 17101, "modes": ALL + ["iodine", "dnscat", "doh", "control"]}}
LONG = {"exfil-slow": 600}


def sh(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
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
    ap.add_argument("--dur", type=int, default=150, help="délka zátěže relace v s (exfil-slow 600)")
    ap.add_argument("--only", default="", help="čárkami oddělené režimy (jen zkouška, ne měření)")
    args = ap.parse_args()
    spec = SETS[args.set]
    modes = list(spec["modes"])
    if args.only:
        modes = [m for m in args.only.split(",") if m in ALL]
    rng = random.Random(spec["seed"])
    rng.shuffle(modes)
    out = os.path.abspath(args.out)
    os.makedirs(os.path.join(out, "pcapb"), exist_ok=True)
    os.environ["LOGDIR"] = out
    labels = open(os.path.join(out, "labels.jsonl"), "a", encoding="utf-8")
    compose("down", "-t", "3")
    compose("up", "-d")
    time.sleep(args.warmup)
    seen = {}
    names = []
    try:
        for i, mode in enumerate(modes):
            rep = seen.get(mode, 0)
            seen[mode] = rep + 1
            label = f"{mode}-{rep}"
            name = f"{P}-cli-{label}"
            names.append(name)
            dur = LONG.get(mode, args.dur) if not args.only else args.dur
            sh(["docker", "rm", "-f", name])
            run = ["docker", "run", "-d", "--name", name, "--network", NET, "--cap-add", "NET_ADMIN",
                   "--cap-add", "NET_RAW", "--device", "/dev/net/tun", "-e", f"DUR={dur}",
                   "-e", f"SEED={spec['seed'] + i}", "-v", f"{os.path.join(LAB, 'rolesb')}:/lab:ro",
                   "-v", f"{out}:/out", IMAGE, "sh", "/lab/tunnel_client.sh", mode, label]
            t0 = time.time()
            r = sh(run)
            if r.returncode != 0:
                labels.write(json.dumps({"relation": label, "mode": mode, "error": r.stderr[-300:]}) + "\n")
                labels.flush()
                continue
            # klient sám skončí po DUR + zahájení/ukončení zachytávání; strop pro jistotu
            deadline = t0 + dur + 45
            while time.time() < deadline:
                st = sh(["docker", "inspect", "-f", "{{.State.Running}}", name]).stdout.strip()
                if st != "true":
                    break
                time.sleep(3)
            sh(["docker", "stop", "-t", "8", name])
            sh(["docker", "rm", "-f", name])
            labels.write(json.dumps({"relation": label, "mode": mode, "set": args.set, "seed": spec["seed"],
                                     "start": t0, "end": time.time(), "dur": dur,
                                     "pcap": f"pcapb/{label}.pcap"}) + "\n")
            labels.flush()
            print(f"{i} {label} hotovo", flush=True)
    finally:
        compose("down", "-t", "5")
        for n in names:
            sh(["docker", "rm", "-f", n])


if __name__ == "__main__":
    main()
