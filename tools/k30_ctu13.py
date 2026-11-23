#!/usr/bin/env python3
"""Krok 30: skutečné botnety CTU-13 přehrané po oknech celou produkční cestou v3.

Postup je předem zapsán v `docs/diplomka/eval/predreg-krok30.md`. Převod binetflow na
conn.log je ztrátový (pakety se dělí úměrně bajtům, stav se bere z `Dir`).

  k30_ctu13.py --csv capture.binetflow.csv --bin salticus-program.exe --work DIR \
      --arm A|B [--scope 147.32.84.0/24] [--window 1800] --out result.json
"""
import argparse
import csv
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone

FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes "
          "resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts "
          "orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents ip_proto").split()
EMPTY_NMAP = ('<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="replay" start="0" version="7.94">\n'
              '<runstats><finished time="0"/><hosts up="0" down="0" total="0"/></runstats>\n</nmaprun>\n')
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
ARM_FLAGS = {"A": "", "B": "attempts,attr_calib,upload_horizon", "C": "outscan", "D": "retry"}
REJ_STATES = ("SR_", "S_R", "S_RA", "SA_R")


def port(value):
    value = (value or "").strip()
    if not value:
        return "-"
    try:
        return str(int(value, 16) if value.lower().startswith("0x") else int(value))
    except ValueError:
        return "-"


def convert(path, v2=True):
    """-> (řádky seřazené podle času, množina infikovaných zdrojů)."""
    rows, infected = [], set()
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        n = 0
        for r in reader:
            # ořezaný soubor končí nekompletním řádkem (chybějící pole = None): přeskočit
            if any(r.get(k) is None for k in ("StartTime", "Dur", "Proto", "SrcAddr", "Sport",
                                              "Dir", "DstAddr", "Dport", "TotPkts", "TotBytes",
                                              "SrcBytes", "Label")):
                continue
            try:
                ts = datetime.strptime(r["StartTime"].strip(), "%Y/%m/%d %H:%M:%S.%f").replace(
                    tzinfo=timezone.utc).timestamp()
                proto = r["Proto"].strip().lower()
                if proto not in ("tcp", "udp", "icmp"):
                    continue
                dur = float(r["Dur"]) if r["Dur"].strip() else 0.0
                tot_b = int(float(r["TotBytes"] or 0))
                src_b = int(float(r["SrcBytes"] or 0))
                tot_p = max(1, int(float(r["TotPkts"] or 1)))
            except (ValueError, KeyError):
                continue
            label = r.get("Label", "")
            src = r["SrcAddr"].strip()
            if "From-Botnet" in label:
                infected.add(src)
            bidir = "<" in r["Dir"]
            share = src_b / tot_b if tot_b else 1.0
            op = min(tot_p, max(1, round(tot_p * share)))
            rp = tot_p - op if bidir else 0
            n += 1
            rows.append((ts, [f"{ts:.6f}", f"Cctu{n:09d}", src, port(r["Sport"]), r["DstAddr"].strip(),
                              port(r["Dport"]), proto, "-", f"{dur:.6f}", str(src_b),
                              str(max(0, tot_b - src_b)) if bidir else "0",
                              state_of(r, bidir, v2), "T", "T", "0", "-", str(op), str(src_b),
                              str(rp), str(max(0, tot_b - src_b)) if bidir else "0", "-",
                              {"tcp": "6", "udp": "17", "icmp": "1"}[proto]]))
    rows.sort(key=lambda x: x[0])
    return rows, infected


def state_of(r, bidir, v2):
    if not v2:  # krok 30: jednosměrný záznam = S0
        return "SF" if bidir else "S0"
    st = (r.get("State") or "").strip()
    if st == "S_":
        return "S0"
    if st in REJ_STATES:
        return "REJ"
    return "SF"


def write_window(path, rows):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "conn.log"), "w", encoding="utf-8", newline="\n") as out:
        out.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        out.write("#fields\t" + "\t".join(FIELDS) + "\n")
        for _, cols in rows:
            out.write("\t".join(cols) + "\n")


def latest_report(workspace):
    best = None
    runs = os.path.join(workspace, "runs")
    for name in os.listdir(runs):
        p = os.path.join(runs, name, "report.json")
        if os.path.exists(p):
            m = os.path.getmtime(p)
            if best is None or m > best[0]:
                best = (m, p)
    with open(best[1], encoding="utf-8") as h:
        return json.load(h)


def load_zeek(path):
    """Zeek conn.log(.labeled), lehce (jen surové řádky): -> (hlavička, [(ts, src, dst, řádek)], infikovaní, scope)."""
    from collections import Counter
    fields, base_n = None, None
    items, infected, nets = [], set(), Counter()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                flat = []
                for f in line.split("\t")[1:]:
                    flat.extend(f.split())
                fields = flat
                base_n = fields.index("tunnel_parents") + 1 if "tunnel_parents" in fields else len(fields)
                continue
            if line.startswith("#") or not line.strip() or fields is None:
                continue
            parts = line.split("\t")
            if len(parts) < len(fields):
                parts = parts[:-1] + parts[-1].split()
            try:
                ts = float(parts[0])
            except ValueError:
                continue
            src, dst = parts[2], parts[4]
            if any("alicious" in x for x in parts[base_n:]):
                infected.add(src)
            try:
                ip = ipaddress.ip_address(src)
                if ip.version == 4 and ip.is_private:
                    nets[str(ipaddress.ip_network(f"{ip}/24", strict=False))] += 1
            except ValueError:
                pass
            items.append((ts, src, dst, "\t".join(parts[:base_n])))
    header = fields[:base_n] if fields else []
    scope = nets.most_common(1)[0][0] if nets else "192.168.1.0/24"
    return header, items, infected, scope


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="binetflow (CTU-13)")
    ap.add_argument("--zeek", help="Zeek conn.log nebo conn.log.labeled")
    ap.add_argument("--bin", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--arm", required=True, choices=sorted(ARM_FLAGS))
    ap.add_argument("--scope")
    ap.add_argument("--window", type=int, default=1800)
    ap.add_argument("--converter", default="v2", choices=["v1", "v2"])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    if a.zeek:
        zheader, items, infected, auto = load_zeek(a.zeek)
        scope = a.scope or auto
        label = os.path.basename(a.zeek)

        def write(path, chunk):
            os.makedirs(path, exist_ok=True)
            with open(os.path.join(path, "conn.log"), "w", encoding="utf-8", newline="\n") as out:
                out.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
                out.write("#fields\t" + "\t".join(zheader) + "\n")
                for x in chunk:
                    out.write(x[3] + "\n")
    else:
        rows, infected = convert(a.csv, v2=a.converter == "v2")
        scope = a.scope or "147.32.84.0/24"
        items = [(ts, cols[2], cols[4], (ts, cols)) for ts, cols in rows]
        label = os.path.basename(a.csv)

        def write(path, chunk):
            write_window(path, [x[3] for x in chunk])

    net = ipaddress.ip_network(scope)

    def inside(ip):
        try:
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False

    items.sort(key=lambda x: x[0])
    t0 = items[0][0]
    windows = defaultdict(list)
    first_flow = {}
    flows_in_scope = defaultdict(int)
    for it in items:
        windows[int((it[0] - t0) // a.window)].append(it)
        if it[1] in infected and (inside(it[1]) or inside(it[2])):
            flows_in_scope[it[1]] += 1
            first_flow.setdefault(it[1], it[0])

    ws = os.path.join(a.work, "ws")
    shutil.rmtree(a.work, ignore_errors=True)
    os.makedirs(ws)
    with open(os.path.join(ws, "salticus.toml"), "w", encoding="utf-8") as cfg:
        cfg.write('[engine]\nmode = "v3"\n')
        if ARM_FLAGS[a.arm]:
            cfg.write("[engine.v3]\n")
            for name in ARM_FLAGS[a.arm].split(","):
                cfg.write(f"{name} = true\n")
    nmap = os.path.join(a.work, "empty-nmap.xml")
    open(nmap, "w", encoding="utf-8").write(EMPTY_NMAP)

    stat = {ip: {"credited": False, "mentioned_any": False, "suppressed_only": False,
                 "closed": False, "unexpected_only": True, "first_display_ts": None,
                 "flows_in_scope": flows_in_scope.get(ip, 0), "first_flow_ts": first_flow.get(ip)}
            for ip in infected}
    displayed_total, failures = 0, 0
    types = defaultdict(int)
    scan_hosts = set()
    order = sorted(windows)
    for index in order:
        start = t0 + index * a.window
        wdir = os.path.join(a.work, "z")
        write(wdir, windows[index])
        env = dict(os.environ)
        env["SALTICUS_REPLAY_NOW"] = datetime.fromtimestamp(start, timezone.utc).isoformat()
        cmd = [a.bin, "beh", "spust", "--workspace", ws, "--nazev", f"w{index}", "--scope", scope,
               "--nmap-xml", nmap, "--zeek-dir", wdir, "--provider", "demo", "--disable-circl"]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            failures += 1
            sys.stderr.write(proc.stderr[-800:])
            continue
        rep = latest_report(ws)
        findings = {f["finding_id"]: f for f in rep.get("findings", [])}
        life = {r["finding_id"]: r for r in rep.get("findingLifecycle", [])}
        for fid, f in findings.items():
            rec = life.get(fid, {})
            displayed = bool(rec.get("displayed"))
            kind = f.get("finding_type")
            if displayed:
                types[kind] += 1
                if kind == "outbound_scan":
                    scan_hosts.add(f.get("host_key"))
            text = json.dumps(f, ensure_ascii=False)
            ips = set(IP_RE.findall(text)) & infected
            for ip in ips:
                s = stat[ip]
                s["mentioned_any"] = True
                if kind != "unexpected_traffic":
                    s["unexpected_only"] = False
                if displayed and kind != "unexpected_traffic":
                    s["credited"] = True
                    if s["first_display_ts"] is None:
                        s["first_display_ts"] = start
                if not displayed and rec.get("disposition") == "suppressed":
                    s["suppressed_only"] = True
                if str(rec.get("disposition", "")).startswith("auto_resolved") or \
                        rec.get("state") in ("auto_resolved", "refuted"):
                    s["closed"] = True
        displayed_total += sum(1 for r in rep.get("findingLifecycle", []) if r.get("displayed"))
        runs = os.path.join(ws, "runs")
        for old in sorted(os.listdir(runs))[:-3]:
            if old.startswith("run-"):
                shutil.rmtree(os.path.join(runs, old), ignore_errors=True)

    result = {"source": label, "arm": a.arm, "scope": scope, "converter": a.converter,
              "windows": len(order), "flows": len(items), "infected": len(infected),
              "failures": failures, "displayed_total": displayed_total, "types": dict(types),
              "outbound_scan_hosts": sorted(h for h in scan_hosts if h), "hosts": stat}
    json.dump(result, open(a.out, "w", encoding="utf-8"), indent=1)
    got = sum(1 for s in stat.values() if s["credited"])
    print(f"{label} arm {a.arm}: okna {len(order)}, toky {len(items)}, infikováno {len(infected)}, "
          f"zachyceno {got}, zobrazeno {displayed_total}, outbound_scan {types.get('outbound_scan', 0)}, "
          f"selhání {failures}")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
