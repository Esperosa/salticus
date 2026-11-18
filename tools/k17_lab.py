#!/usr/bin/env python3
"""Krok 17, laboratoř A: generátor poruch se štítky (docs/diplomka/eval/impl-krok17.md).

Spustí `labs/k17/compose.yml`, po zahřátí projde sloty (150 s normál, 150 s porucha nebo útok,
150 s po obnově) v pořadí daném semínkem a zapíše štítky do `<out>/labels.jsonl`. Vše se děje
jen uvnitř laboratorních sítí 10.77.0.0/16; nic se neposílá ven.

Pouziti:
  python -I tools/k17_lab.py --set debug --seed 17001 --out F:/Projekty/bakula-datasets/lab-k17/debug
"""
import argparse
import json
import os
import random
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB = os.path.join(ROOT, "labs", "k17")
P = "k17a"
CLIENTS = {"c1": "10.77.1.11", "c2": "10.77.1.12", "c3": "10.77.1.13", "c4": "10.77.1.14"}
FAULTS = ["S01", "S02", "S03", "S04", "S05", "S06", "S07", "S08", "S09", "S10", "S11", "S12", "S13",
          "S14", "S15"]
SETS = {"debug": FAULTS + ["K1", "K2", "A1", "A2", "A3"], "held": FAULTS + ["K1", "K2", "K3", "A1", "A2", "A3"]}
PHASE = 150


def sh(cmd, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}: {r.stderr[-500:]}")
    return r


def dx(svc, script, detach=False):
    cmd = ["docker", "exec"] + (["-d"] if detach else []) + [f"{P}-{svc}-1", "sh", "-c", script]
    return sh(cmd)


def compose(*args, env=None):
    return sh(["docker", "compose", "-p", P, "-f", os.path.join(LAB, "compose.yml")] + list(args), check=True)


def router_ifs():
    lan = dx("router", "cat /tmp/lan_if").stdout.strip()
    srv = dx("router", "cat /tmp/srv_if").stdout.strip()
    return lan, srv


def gratuitous(svc, ip):
    return dx(svc, "python3 -c \"from scapy.all import *; m=get_if_hwaddr('eth0'); "
                   f"sendp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op=2,psrc='{ip}',pdst='{ip}',hwsrc=m),iface='eth0',count=3,verbose=False)\"")


def scenario(sid, rnd, out):
    """Vrátí (params, inject, restore) pro scénář; inject a restore jsou funkce bez argumentů."""
    names = sorted(CLIENTS)
    lan, srv = router_ifs()
    p = {}

    def noop():
        pass

    if sid == "S01":
        return p, lambda: dx("dhcp", "touch /tmp/stop; pkill dnsmasq"), lambda: dx("dhcp", "rm -f /tmp/stop")
    if sid == "S02":
        v = rnd.choice(names)
        p.update(victim=v, victim_ip=CLIENTS[v], extra=6)
        inj = ("for i in 1 2 3 4 5 6; do ip link add m$i link eth0 type macvlan mode bridge; ip link set m$i up; "
               "udhcpc -i m$i -s /tmp/noop.sh -S -b -t 5 -T 3 -A 10 >/dev/null 2>&1; done")
        rst = "pkill -f 'udhcpc -i [m]'; for i in 1 2 3 4 5 6; do ip link del m$i 2>/dev/null; done"
        # odpojeně: sekvenční udhcpc by jinak blokovaly slot o desítky sekund
        return p, lambda: dx(v, inj, detach=True), lambda: dx(v, rst)
    if sid == "S03":
        return p, lambda: dx("auth", "touch /tmp/stop; pkill nsd"), lambda: dx("auth", "rm -f /tmp/stop")

    if sid == "S04":
        def inj():
            dx("auth", "echo 10.77.2.11 > /tmp/app_ip; pkill nsd")
            dx("web", "touch /tmp/app-moved")

        def rst():
            dx("auth", "echo 10.77.2.10 > /tmp/app_ip; pkill nsd")
            dx("web", "rm -f /tmp/app-moved")
            time.sleep(2)
            dx("resolver", "unbound-control flush_zone lab.test")
        return p, inj, rst
    if sid == "S05":
        d = rnd.randint(1200, 2500)
        p.update(delay_ms=d)
        return p, lambda: dx("resolver", f"tc qdisc add dev eth0 root netem delay {d}ms"), \
            lambda: dx("resolver", "tc qdisc del dev eth0 root")
    if sid in ("S06", "A3"):
        loss = rnd.randint(15, 30)
        p.update(loss_pct=loss)
        base = "tc qdisc change dev {i} root netem rate 20mbit limit 200"
        inj6 = lambda: dx("router", "; ".join(base.format(i=i) + f" loss {loss}%" for i in (lan, srv)))
        rst6 = lambda: dx("router", "; ".join(base.format(i=i) for i in (lan, srv)))
        if sid == "S06":
            return p, inj6, rst6
        s = rnd.choice(names)
        p.update(scanner=s, scanner_ip=CLIENTS[s])
        scan = f"timeout {PHASE - 5} nmap -sS -T4 -n -Pn --max-retries 1 -p 1-200 10.77.2.0/24 >/dev/null 2>&1"

        def inj_a3():
            inj6()
            dx(s, scan, detach=True)
        return p, inj_a3, rst6
    if sid == "S07":
        vs = rnd.sample(names, 2)
        p.update(victims=vs, victim_ips=[CLIENTS[v] for v in vs], streams=3)
        loop = (f"for k in 1 2 3; do timeout {PHASE - 5} sh -c 'while true; do curl -s -m 30 -o /dev/null "
                "http://files.lab.test/file; done' & done; wait")
        return p, lambda: [dx(v, loop, detach=True) for v in vs], noop
    if sid == "S08":
        p.update(mtu=1200)
        inj = (f"ip link set dev {lan} mtu 1200; "
               "iptables -A OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP")
        rst = (f"ip link set dev {lan} mtu 1500; "
               "iptables -D OUTPUT -p icmp --icmp-type fragmentation-needed -j DROP")
        return p, lambda: dx("router", inj), lambda: dx("router", rst)
    if sid == "S09":
        p.update(kill_every_s=12)
        loop = f"timeout {PHASE - 5} sh -c 'while true; do sleep 12; pkill -9 -f \"[p]ython3 /lab/app.py\"; done'"
        return p, lambda: dx("web", loop, detach=True), noop
    if sid == "S10":
        sw = "cp /tmp/tls/{c}.crt /tmp/tls/cur.crt; cp /tmp/tls/{c}.key /tmp/tls/cur.key; nginx -s reload"
        return p, lambda: dx("web", sw.format(c="expired")), lambda: dx("web", sw.format(c="valid"))
    if sid == "S11":
        off = round(rnd.uniform(3, 30), 1)
        p.update(offset_s=off)

        def inj():
            dx("ntp", "touch /tmp/stop; pkill chronyd")
            time.sleep(1)
            dx("ntp", f"timeout {PHASE} python3 /lab/fakentp.py {off}", detach=True)
        return p, inj, lambda: dx("ntp", "pkill -f [f]akentp.py; sleep 1; pkill -9 -f [f]akentp.py; rm -f /tmp/stop")
    if sid == "S12":
        return p, lambda: dx("ntp", "touch /tmp/stop; pkill chronyd"), lambda: dx("ntp", "rm -f /tmp/stop")
    if sid == "S13":
        a, b = rnd.sample(names, 2)
        ip = CLIENTS[a]
        p.update(owner=a, owner_ip=ip, duplicate=b, duplicate_ip=CLIENTS[b])
        loop = (f"timeout {PHASE - 5} sh -c 'while true; do curl -s -m 5 -o /dev/null --interface {ip} "
                "http://web.lab.test/; sleep 3; done'")

        def inj():
            dx(b, f"ip addr add {ip}/24 dev eth0")
            gratuitous(b, ip)
            dx(b, loop, detach=True)
        return p, inj, lambda: dx(b, f"ip addr del {ip}/24 dev eth0")
    if sid == "S14":
        p.update(new_ip="10.77.1.100")  # mimo auto-pool /26, aby nekolidovala s přidělením
        logdir = os.environ["LOGDIR"]
        run = ["docker", "run", "-d", "--rm", "--name", f"{P}-newdev-1", "--network", f"{P}_lan", "--ip", "10.77.1.100",
               "--hostname", "newdev", "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
               "-v", f"{os.path.join(LAB, 'roles')}:/lab:ro", "-v", f"{logdir}:/out", "k17lab:1",
               "sh", "/lab/client.sh", "client"]
        return p, lambda: sh(run), lambda: sh(["docker", "rm", "-f", f"{P}-newdev-1"])
    if sid == "S15":
        return p, lambda: dx("web", "python3 /lab/fill.py"), lambda: dx("web", "rm -f /data/fill-*")
    if sid.startswith("K"):
        return p, noop, noop
    if sid == "A1":
        s = rnd.choice(names)
        p.update(scanner=s, scanner_ip=CLIENTS[s])
        scan = f"timeout {PHASE - 5} nmap -sS -T4 -n -Pn --max-retries 1 -p 1-200 10.77.2.0/24 >/dev/null 2>&1"
        return p, lambda: dx(s, scan, detach=True), noop
    if sid == "A2":
        a, v = rnd.sample(names, 2)
        p.update(attacker=a, attacker_ip=CLIENTS[a], victim=v, victim_ip=CLIENTS[v])
        return p, lambda: dx(a, f"timeout {PHASE} python3 /lab/mitm.py {CLIENTS[v]} 10.77.1.254 {PHASE - 5}",
                             detach=True), \
            lambda: (dx(v, "ping -c 2 -W 1 10.77.1.254 >/dev/null"), dx("router", f"ping -c 2 -W 1 {CLIENTS[v]} >/dev/null"))
    raise ValueError(sid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True, choices=sorted(SETS))
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--warmup", type=int, default=300)
    ap.add_argument("--only", default="", help="ladeni: jen vyjmenovane sloty (carkou)")
    ap.add_argument("--phase", type=int, default=150, help="delka faze v s (jen kontrola skriptu)")
    args = ap.parse_args()
    global PHASE
    PHASE = args.phase
    os.makedirs(args.out, exist_ok=True)
    os.environ["LOGDIR"] = os.path.abspath(args.out)
    rnd = random.Random(args.seed)
    order = SETS[args.set][:]
    rnd.shuffle(order)
    if args.only:
        order = [s for s in args.only.split(",")]
    labels = open(os.path.join(args.out, "labels.jsonl"), "a", encoding="utf-8")

    def label(rec):
        labels.write(json.dumps(rec) + "\n")
        labels.flush()

    sh(["docker", "compose", "-p", P, "-f", os.path.join(LAB, "compose.yml"), "down", "-t", "2"])
    compose("up", "-d")
    t = time.time()
    label({"slot": "warmup", "start": t, "end": t + args.warmup, "set": args.set, "seed": args.seed})
    time.sleep(args.warmup)
    try:
        for n, sid in enumerate(order):
            params, inject, restore = scenario(sid, rnd, args.out)
            t0 = time.time()
            time.sleep(PHASE)
            tf = time.time()
            inject()
            time.sleep(max(0, tf + PHASE - time.time()))
            te = time.time()
            restore()
            time.sleep(max(0, te + PHASE - time.time()))
            label({"slot": n, "scenario": sid, "set": args.set, "seed": args.seed, "start": t0, "fault_start": tf,
                   "fault_end": te, "end": time.time(), "params": params})
            print(f"{n} {sid} hotovo", flush=True)
    finally:
        time.sleep(5)
        sh(["docker", "compose", "-p", P, "-f", os.path.join(LAB, "compose.yml"), "down", "-t", "5"])
        sh(["docker", "rm", "-f", f"{P}-newdev-1"])


if __name__ == "__main__":
    sys.exit(main())
