#!/usr/bin/env python3
"""Krok 17, laboratoř B: detekce DNS tunelu produkční cestou (impl-krok17.md, T1 a T2).

Pro každou relaci (pcap z `tools/k17_labb.py`): Zeek (`zeek -C -r`), pak jedno `beh spust
--zeek-dir` se `l7_dns,l7_tls`; zjistí nálezy `dns_tunnel_names` a `dns_zone_enumeration`.
Vyhodnotí detekci podle režimu (iodine, dnscat, doh, control) a falešné poplachy na kontrole.
Navíc vypíše z Zeek dns.log tvar jmen (počet jmen, průměrná délka štítku, podíl TXT/NULL),
aby bylo vidět, proč detektor zabral nebo ne.

Pouziti:
  python -I tools/k17_evalb.py --set-dir F:/Projekty/bakula-datasets/lab-k17/debugB --bin BIN
"""
import argparse
import glob
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

EMPTY_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="replay" start="0" version="7.94">
<runstats><finished time="0"/><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>
"""
TUNNEL_TYPES = {"dns_tunnel_names", "dns_zone_enumeration"}


def zeek(pcap, out):
    os.makedirs(out, exist_ok=True)
    if not os.path.exists(os.path.join(out, "dns.log")) and not os.path.exists(os.path.join(out, "conn.log")):
        subprocess.run(["docker", "run", "--rm", "-v", f"{os.path.dirname(pcap)}:/pcap:ro", "-v", f"{out}:/out",
                        "-w", "/out", "zeek/zeek:9.0.1", "zeek", "-C", "-r", f"/pcap/{os.path.basename(pcap)}"],
                       capture_output=True, check=False)
    return out


def dns_shape(zdir):
    path = os.path.join(zdir, "dns.log")
    if not os.path.exists(path):
        return {}
    cols, rows = [], []
    with open(path, encoding="utf-8", errors="replace") as h:
        for line in h:
            if line.startswith("#fields"):
                cols = line.split("\t")[1:]
            elif not line.startswith("#") and line.strip():
                rows.append(line.rstrip("\n").split("\t"))
    if not cols:
        return {}
    qi = cols.index("query") if "query" in cols else None
    ti = cols.index("qtype_name") if "qtype_name" in cols else None
    by_zone = defaultdict(lambda: {"names": set(), "labels": [], "txt": 0, "total": 0})
    for r in rows:
        if qi is None or qi >= len(r):
            continue
        q = r[qi]
        qt = r[ti] if ti is not None and ti < len(r) else ""
        zone = ".".join(q.split(".")[-3:]) if q.count(".") >= 2 else q
        z = by_zone[zone]
        z["names"].add(q)
        z["labels"].append(q.split(".")[0])
        z["total"] += 1
        if qt in ("TXT", "NULL", "PRIVATE"):
            z["txt"] += 1
    out = {}
    for zone, z in by_zone.items():
        if z["total"] < 5:
            continue
        labs = z["labels"]
        avg_len = sum(len(x) for x in labs) / len(labs)
        ent = []
        for x in set(labs):
            if not x:
                continue
            c = Counter(x)
            ent.append(-sum((v / len(x)) * math.log2(v / len(x)) for v in c.values()))
        out[zone] = {"names": len(z["names"]), "avg_label_len": round(avg_len, 1),
                     "avg_entropy": round(sum(ent) / len(ent), 2) if ent else 0,
                     "txt_ratio": round(z["txt"] / z["total"], 2), "queries": z["total"]}
    return out


def run_detect(binp, set_dir, zdir, label):
    ws = os.path.join(set_dir, "eval", "ws-" + label)
    os.makedirs(os.path.join(ws, "runs"), exist_ok=True)
    with open(os.path.join(ws, "salticus.toml"), "w", encoding="utf-8") as c:
        c.write('[engine]\nmode = "v3"\n[engine.v3]\nprotect = true\nl7_dns = true\nl7_tls = true\n')
    nmap = os.path.join(set_dir, "eval", "empty.xml")
    os.makedirs(os.path.dirname(nmap), exist_ok=True)
    open(nmap, "w", encoding="utf-8").write(EMPTY_NMAP)
    env = dict(os.environ, RUST_LOG="error")
    r = subprocess.run([binp, "beh", "spust", "--workspace", ws, "--nazev", label, "--scope", "10.88.0.0/16",
                        "--nmap-xml", nmap, "--zeek-dir", zdir, "--provider", "demo", "--disable-circl"],
                       capture_output=True, text=True, env=env, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        return {"error": r.stderr[-400:]}
    best = max(glob.glob(os.path.join(ws, "runs", "*", "report.json")), key=os.path.getmtime)
    rep = json.load(open(best, encoding="utf-8"))
    finds = {f["finding_id"]: f for f in rep.get("findings", [])}
    tunnel = []
    for lc in rep.get("findingLifecycle", []):
        f = finds.get(lc["finding_id"], {})
        if f.get("finding_type") in TUNNEL_TYPES:
            tunnel.append({"type": f.get("finding_type"), "displayed": lc.get("displayed"),
                           "title": str(f.get("title", ""))[:120]})
    return {"tunnel_findings": tunnel, "n_findings": len(rep.get("findings", []))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-dir", required=True)
    ap.add_argument("--bin", required=True)
    args = ap.parse_args()
    labels = [json.loads(l) for l in open(os.path.join(args.set_dir, "labels.jsonl"), encoding="utf-8") if l.strip()]
    per_mode = defaultdict(lambda: {"relations": 0, "detected": 0})
    fp = 0
    details = []
    for rec in labels:
        if "pcap" not in rec:
            continue
        label, mode = rec["relation"], rec["mode"]
        pcap = os.path.join(args.set_dir, rec["pcap"])
        if not os.path.exists(pcap):
            details.append({"relation": label, "error": "pcap chybí"})
            continue
        zdir = zeek(pcap, os.path.join(args.set_dir, "eval", "zeek-" + label))
        shape = dns_shape(zdir)
        det = run_detect(args.bin, args.set_dir, zdir, label)
        tun = det.get("tunnel_findings", [])
        hit = any(t["displayed"] for t in tun)
        per_mode[mode]["relations"] += 1
        if hit and mode != "control":
            per_mode[mode]["detected"] += 1
        if hit and mode in ("control", "doh"):
            fp += 1
        details.append({"relation": label, "mode": mode, "detekce": hit,
                        "tunnel_findings": [t["type"] for t in tun if t["displayed"]],
                        "dns_shape": shape, "n_findings": det.get("n_findings"), "error": det.get("error")})
    summary = {"per_mode": {m: f"{v['detected']}/{v['relations']}" for m, v in per_mode.items()},
               "falesne_poplachy_kontrola_doh": fp, "detaily": details}
    json.dump(summary, open(os.path.join(args.set_dir, "eval", "tunnel.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
