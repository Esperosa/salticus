#!/usr/bin/env python3
"""Krok 13, bod 2: reálné přehrání pcap -> Zeek -> Salticus (produkční cesta v3).

Vstup: adresář s logy Zeeku (conn, dns, ssl, x509) z `zeek -C -r X.pcap`. Logy se
rozdělí podle času na okna (výchozí 1800 s); každé okno je adresář s výřezem všech
čtyř logů a projde `salticus-program beh spust --zeek-dir` (stejně jako ve
`replay_public.py`, ale se skutečnými L7 logy). Štítky nejsou: škodlivý je host zadaný
`--bad` (CTU-13: infikovaný 147.32.84.165), vše ostatní je neškodné. Vyhodnocení je na
úrovni hostů: zobrazený nález, který host zmiňuje (host_key nebo IP v textu).

Pouziti:
  python -I tools/k13_replay_zeek.py --logs DIR --bin BIN --work DIR --scope CIDR
         --bad IP [--v3 "l7_tls,l7_dns"] [--window 1800] [--out FILE]
"""
import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

LOGS = ("conn", "dns", "ssl", "x509")
EMPTY_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="replay" start="0" version="7.94">
<runstats><finished time="0"/><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>
"""


def read_log(path):
    head, rows = [], []
    if not os.path.exists(path):
        return head, rows
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("#"):
                if not line.startswith("#close"):
                    head.append(line)
            elif line.strip():
                try:
                    rows.append((float(line.split("\t", 1)[0]), line))
                except ValueError:
                    pass
    return head, rows


def latest_report(workspace):
    best = None
    runs = os.path.join(workspace, "runs")
    for name in os.listdir(runs):
        path = os.path.join(runs, name, "report.json")
        if os.path.exists(path):
            mtime = os.path.getmtime(path)
            if best is None or mtime > best[0]:
                best = (mtime, path)
    with open(best[1], encoding="utf-8") as handle:
        return json.load(handle)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--bad", action="append", default=[])
    ap.add_argument("--v3", default="")
    ap.add_argument("--window", type=int, default=1800)
    ap.add_argument("--max-windows", type=int, default=0)
    ap.add_argument("--name", default="")
    ap.add_argument("--out")
    args = ap.parse_args()

    data = {n: read_log(os.path.join(args.logs, n + ".log")) for n in LOGS}
    conn_rows = data["conn"][1]
    if not conn_rows:
        sys.exit("zadne toky")
    conn_rows.sort()
    t0 = conn_rows[0][0]
    bad = set(args.bad)
    wins = defaultdict(lambda: {n: [] for n in LOGS})
    for n in LOGS:
        for ts, line in data[n][1]:
            wins[max(0, int((ts - t0) // args.window))][n].append(line)
    order = sorted(wins)
    if args.max_windows:
        order = order[: args.max_windows]

    os.makedirs(args.work, exist_ok=True)
    workspace = os.path.join(args.work, "ws")
    os.makedirs(workspace, exist_ok=True)
    with open(os.path.join(workspace, "salticus.toml"), "w", encoding="utf-8") as cfg:
        cfg.write('[engine]\nmode = "v3"\n[engine.v3]\nprotect = true\n')
        for name in filter(None, (s.strip() for s in args.v3.split(","))):
            cfg.write(f"{name} = true\n")
    nmap = os.path.join(args.work, "empty-nmap.xml")
    with open(nmap, "w", encoding="utf-8") as handle:
        handle.write(EMPTY_NMAP)

    total = Counter()
    types = Counter()
    types_bad = Counter()
    first_bad = None
    shown_bad = shown_other = 0
    hosts_other = set()
    failures = 0
    for index in order:
        wdir = os.path.join(args.work, f"w{index:05d}", "zeek")
        os.makedirs(wdir, exist_ok=True)
        for n in LOGS:
            lines = wins[index][n]
            if not lines:
                continue
            with open(os.path.join(wdir, n + ".log"), "w", encoding="utf-8", newline="\n") as out:
                out.write("\n".join(data[n][0]) + "\n" + "\n".join(lines) + "\n")
        start = t0 + index * args.window
        env = dict(os.environ)
        env["SALTICUS_REPLAY_NOW"] = datetime.fromtimestamp(start, timezone.utc).isoformat()
        cmd = [args.bin, "beh", "spust", "--workspace", workspace, "--nazev", f"w{index}",
               "--scope", args.scope, "--nmap-xml", nmap, "--zeek-dir", wdir,
               "--provider", "demo", "--disable-circl"]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            failures += 1
            sys.stderr.write(proc.stderr[-1500:])
            continue
        report = latest_report(workspace)
        findings = {f["finding_id"]: f for f in report.get("findings", [])}
        total["windows"] += 1
        total["flows"] += len(wins[index]["conn"])
        for n in ("dns", "ssl"):
            total[n] += len(wins[index][n])
        for record in report.get("findingLifecycle", []):
            if not record.get("displayed"):
                continue
            f = findings.get(record["finding_id"], {})
            text = " ".join([str(f.get("title", "")), str(f.get("rationale", "")), str(f.get("host_key", ""))]
                            + [str(e) for e in f.get("evidence", [])])
            ips = set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
            kind = str(f.get("kind") or f.get("finding_kind") or f.get("title", ""))[:60]
            if ips & bad:
                shown_bad += 1
                types_bad[kind] += 1
                if first_bad is None:
                    first_bad = index
            else:
                shown_other += 1
                types[kind] += 1
                hosts_other.add(f.get("host_key") or "")
    title = args.name or os.path.basename(args.logs.rstrip("/"))
    lines = [f"### `{title}` v3 [{args.v3 or 'bez L7'}]", "",
             f"Oken {total['windows']} po {args.window} s (selhalo {failures}), toků {total['flows']}, "
             f"DNS řádků {total['dns']}, TLS řádků {total['ssl']}, škodlivý host {','.join(sorted(bad)) or '-'}.", "",
             f"- zobrazených nálezů zmiňujících škodlivý host: {shown_bad}, první v okně {first_bad if first_bad is not None else '-'}",
             f"- zobrazených nálezů o jiných hostech: {shown_other} (různých hostů {len(hosts_other)})",
             "- typy (škodlivý): " + ", ".join(f"{k} {v}" for k, v in types_bad.most_common(6)),
             "- typy (jiné): " + ", ".join(f"{k} {v}" for k, v in types.most_common(6)), ""]
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "a", encoding="utf-8") as handle:
            handle.write(text)
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
