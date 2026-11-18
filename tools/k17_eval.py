#!/usr/bin/env python3
"""Krok 17, laboratoř A: vyhodnocení produkční cestou (docs/diplomka/eval/impl-krok17.md).

Vstup: adresář sady z `tools/k17_lab.py` (labels.jsonl, logs/, pcap/). Kroky:
1. Zeek na pcap (docker zeek/zeek, `zeek -C -r`), logy do <set>/zeek/.
2. Okna podle fází slotů. Pro každé okno: `ops ingest` (syslog, snmp, nagios, dhcp, arp) se
   `SALTICUS_REPLAY_NOW` = konec okna, pak `beh spust --zeek-dir` se stejným časem (M2, jeden
   pracovní prostor na rameno).
3. M1: pro každý slot samostatný pracovní prostor jen s telemetrií slotu (normál + porucha),
   `ops diagnose` v čase konce poruchy pro předem daný typ a hosty; a totéž bez SNMP a syslogu (C3).
Výstup: <set>/eval/<arm>/... a souhrn JSON + Markdown na stdout.

Pouziti:
  python -I tools/k17_eval.py --set-dir F:/Projekty/bakula-datasets/lab-k17/debug --bin BIN [--skip-m2]
"""
import argparse
import glob
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

LOGS = ("conn", "dns", "ssl", "x509", "http")
CLIENT_IPS = ["10.77.1.11", "10.77.1.12", "10.77.1.13", "10.77.1.14"]
INFRA = ["10.77.1.254", "10.77.2.254", "10.77.2.53", "10.77.2.54", "10.77.2.123", "10.77.1.2"]
EXPECT = {  # scénář -> (třída, přijatelná catalog_id) ; zapsáno v předregistraci
    "S01": ("porucha", {"OPS-004"}), "S02": ("porucha", {"OPS-003"}), "S03": ("porucha", {"OPS-005"}),
    "S04": ("porucha", {"OPS-029"}), "S05": ("porucha", {"OPS-006"}),
    "S06": ("porucha", {"OPS-020", "OPS-045", "OPS-046"}), "S07": ("porucha", {"OPS-011"}),
    "S08": ("porucha", {"OPS-035"}), "S09": ("porucha", {"OPS-016", "OPS-019", "OPS-054"}),
    "S10": ("porucha", {"OPS-009"}), "S11": ("porucha", {"OPS-008"}), "S12": ("porucha", {"OPS-007"}),
    "S13": ("porucha", {"OPS-015"}), "S14": ("zmena", {"CHG-013"}), "S15": ("porucha", {"OPS-021"}),
}
EMPTY_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="replay" start="0" version="7.94">
<runstats><finished time="0"/><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>
"""
ARMS = {"ops": ["ops_telemetry"], "k15ops": ["ops_telemetry", "ops_symptoms", "ops_blast"]}


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def run(cmd, now=None, check=True):
    env = dict(os.environ)
    if now is not None:
        env["SALTICUS_REPLAY_NOW"] = iso(now)
    env["RUST_LOG"] = "error"
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        sys.stderr.write(f"FAIL {' '.join(cmd[:4])}: {r.stderr[-800:]}\n")
    return r


def zeek(set_dir):
    out = os.path.join(set_dir, "zeek")
    if os.path.exists(os.path.join(out, "done")):
        return out
    os.makedirs(out, exist_ok=True)
    for pcap in sorted(glob.glob(os.path.join(set_dir, "pcap", "*.pcap"))):
        name = os.path.splitext(os.path.basename(pcap))[0]
        part = os.path.join(out, name)
        os.makedirs(part, exist_ok=True)
        subprocess.run(["docker", "run", "--rm", "-v", f"{os.path.dirname(pcap)}:/pcap:ro", "-v", f"{part}:/out",
                        "-w", "/out", "zeek/zeek:9.0.1", "zeek", "-C", "-r", f"/pcap/{os.path.basename(pcap)}"],
                       capture_output=True, check=False)
    open(os.path.join(out, "done"), "w").close()
    return out


def read_zeek(zdir):
    data = {}
    for n in LOGS:
        head, rows = [], []
        for path in sorted(glob.glob(os.path.join(zdir, "*", n + ".log"))):
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.rstrip("\n")
                    if line.startswith("#"):
                        if not head or not line.startswith("#close"):
                            if len(head) < 8 and not line.startswith("#close"):
                                head.append(line)
                    elif line.strip():
                        try:
                            rows.append((float(line.split("\t", 1)[0]), line))
                        except ValueError:
                            pass
        rows.sort()
        data[n] = (head[:8], rows)
    return data


def read_ops(set_dir):
    """Řádky telemetrie s časem: (ts, formát, řádek)."""
    out = []
    logs = os.path.join(set_dir, "logs")
    with open(os.path.join(logs, "syslog.log"), encoding="utf-8", errors="replace") as h:
        for line in h:
            line = line.rstrip("\n")
            parts = line.split(" ", 4)
            if len(parts) < 5:
                continue
            try:
                ts = datetime.fromisoformat(parts[1]).timestamp()
            except ValueError:
                continue
            app = parts[3]
            out.append((ts, "syslog", line))
            if app in ("dnsmasq-dhcp", "udhcpc"):
                out.append((ts, "dhcp", line))
            if app == "arpwatch":
                out.append((ts, "arp", line))
    path = os.path.join(logs, "nagios.log")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as h:
            for line in h:
                m = re.match(r"\[(\d+)\]", line)
                if m:
                    out.append((float(m.group(1)), "nagios", line.rstrip("\n")))
    path = os.path.join(logs, "snmp.log")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as h:
            for line in h:
                ts, _, rest = line.rstrip("\n").partition("\t")
                if rest and not rest.startswith("#"):
                    out.append((float(ts), "snmp", rest))
    out.sort(key=lambda x: x[0])
    return out


def windows(labels):
    wins = []
    for rec in labels:
        if rec["slot"] == "warmup":
            mid = (rec["start"] + rec["end"]) / 2
            wins += [(rec["start"], mid, "warmup", "pre", rec), (mid, rec["end"], "warmup", "pre", rec)]
            continue
        wins += [(rec["start"], rec["fault_start"], rec["scenario"], "pre", rec),
                 (rec["fault_start"], rec["fault_end"], rec["scenario"], "fault", rec),
                 (rec["fault_end"], rec["end"], rec["scenario"], "post", rec)]
    return wins


def ingest(bin_path, ws, lines, now, formats, tmp):
    by = defaultdict(list)
    for _, fmt, line in lines:
        if fmt in formats:
            by[fmt].append(line)
    os.makedirs(tmp, exist_ok=True)
    for fmt in formats:
        path = os.path.join(tmp, f"{fmt}.txt")
        with open(path, "w", encoding="utf-8", newline="\n") as h:
            h.write("\n".join(by.get(fmt, [])) + "\n")
        # i prázdná dávka je heartbeat zdroje (sběrač běží, jen nehlásí nic)
        run([bin_path, "ops", "ingest", "--workspace", ws, "--format", fmt, "--file", path], now=now)


def write_cfg(ws, flags):
    os.makedirs(ws, exist_ok=True)
    with open(os.path.join(ws, "salticus.toml"), "w", encoding="utf-8") as cfg:
        cfg.write('[engine]\nmode = "v3"\n[engine.v3]\nprotect = true\nl7_dns = true\nl7_tls = true\n')
        for f in flags:
            cfg.write(f"{f} = true\n")


def latest_report(ws):
    best = None
    for path in glob.glob(os.path.join(ws, "runs", "*", "report.json")):
        m = os.path.getmtime(path)
        if best is None or m > best[0]:
            best = (m, path)
    with open(best[1], encoding="utf-8") as h:
        return json.load(h)


def slot_ips(sid, p, rnd):
    """Předem daný typ nálezu a hosty pro M1 (předregistrace, bod 3)."""
    if sid in ("S06", "S07", "S08"):
        typ = "connection_timeout_burst"
    elif sid == "S14":
        typ = "new_device"
    else:
        typ = "service_unreachable"
    ips = {
        "S01": ["10.77.1.2"] + CLIENT_IPS, "S02": ["10.77.1.2", p.get("victim_ip", "")],
        "S03": ["10.77.2.54", "10.77.2.53"], "S04": ["10.77.2.10", "10.77.2.53"], "S05": ["10.77.2.53"],
        "S06": ["10.77.1.254", "10.77.2.10"], "S07": ["10.77.1.254"] + p.get("victim_ips", []),
        "S08": ["10.77.1.254", "10.77.2.10"], "S09": ["10.77.2.10"], "S10": ["10.77.2.10"],
        "S11": ["10.77.2.123"] + CLIENT_IPS, "S12": ["10.77.2.123"], "S13": [p.get("owner_ip", "")],
        "S14": [p.get("new_ip", "10.77.1.40")], "S15": ["10.77.2.10"],
    }
    if sid in ips:
        return [(typ, [i for i in ips[sid] if i])]
    if sid.startswith("K"):
        return [("service_unreachable", [rnd.choice(["10.77.2.10", "10.77.2.53", "10.77.2.123"])])]
    if sid in ("A1", "A3"):
        return [("scan_attempts", [p["scanner_ip"]]), ("unexpected_traffic", [p["scanner_ip"]])]
    if sid == "A2":
        return [("unexpected_traffic", [p["attacker_ip"]]), ("unexpected_traffic", [p["victim_ip"]])]
    return []


def present_keys(ws, lo, hi):
    db = os.path.join(ws, "engine-state.sqlite")
    keys = Counter()
    if not os.path.exists(db):
        return keys
    con = sqlite3.connect(db)
    for (body,) in con.execute("SELECT body FROM ops_signals WHERE ts >= ? AND ts <= ?", (int(lo), int(hi) + 1)):
        s = json.loads(body)
        keys[s["key"]] += 1
    con.close()
    return keys


def m1(bin_path, set_dir, labels, ops_lines, catalog, arm, nodata=False):
    root = os.path.join(set_dir, "eval", "m1-" + arm + ("-nodata" if nodata else ""))
    shutil.rmtree(root, ignore_errors=True)
    rnd = random.Random(17)
    formats = ("nagios", "dhcp", "arp") if nodata else ("syslog", "snmp", "nagios", "dhcp", "arp")
    results = []
    warm = next(r for r in labels if r["slot"] == "warmup")
    for rec in labels:
        if rec["slot"] == "warmup":
            continue
        ws = os.path.join(root, f"slot{rec['slot']:02d}-{rec['scenario']}")
        tmp = os.path.join(ws, "in")
        # heartbeat zdrojů z konce zahřátí, pak normál a porucha slotu (bez jiných slotů)
        hb = [x for x in ops_lines if warm["end"] - 150 <= x[0] < warm["end"]]
        ingest(bin_path, ws, hb, warm["end"], formats, tmp)
        for lo, hi in ((rec["start"], rec["fault_start"]), (rec["fault_start"], rec["fault_end"])):
            ingest(bin_path, ws, [x for x in ops_lines if lo <= x[0] < hi], hi, formats, tmp)
        keys = present_keys(ws, rec["fault_start"] - 5, rec["fault_end"] + 5)
        for typ, ips in slot_ips(rec["scenario"], rec["params"], rnd):
            cmd = [bin_path, "ops", "diagnose", "--workspace", ws, "--typ", typ]
            for ip in ips:
                cmd += ["--ip", ip]
            if arm == "k15ops":
                cmd += ["--symptoms", "--blast"] + sum((["--infra", i] for i in INFRA), [])
            r = run(cmd, now=rec["fault_end"])
            try:
                d = json.loads(r.stdout.strip().splitlines()[-1])
            except (IndexError, json.JSONDecodeError):
                d = {"class": "chyba", "reason": r.stderr[-200:]}
            results.append({"slot": rec["slot"], "scenario": rec["scenario"], "typ": typ, "ips": ips,
                            "class": d.get("class"), "catalog_id": d.get("catalog_id"),
                            "candidates": d.get("candidates", []), "evidence": d.get("evidence", []),
                            "reason": d.get("reason"), "missing": d.get("missing", []),
                            "keys_fault": dict(keys)})
    return results


def m2(bin_path, set_dir, labels, ops_lines, zdata, arm):
    ws = os.path.join(set_dir, "eval", "m2-" + arm)
    shutil.rmtree(ws, ignore_errors=True)
    write_cfg(ws, ARMS[arm])
    nmap = os.path.join(set_dir, "eval", "empty-nmap.xml")
    with open(nmap, "w", encoding="utf-8") as h:
        h.write(EMPTY_NMAP)
    out = []
    for i, (lo, hi, sid, phase, rec) in enumerate(windows(labels)):
        wdir = os.path.join(set_dir, "eval", "win", f"w{i:03d}")
        zdir = os.path.join(wdir, "zeek")
        os.makedirs(zdir, exist_ok=True)
        for n in LOGS:
            head, rows = zdata[n]
            sel = [line for ts, line in rows if lo <= ts < hi]
            if sel:
                with open(os.path.join(zdir, n + ".log"), "w", encoding="utf-8", newline="\n") as h:
                    h.write("\n".join(head) + "\n" + "\n".join(sel) + "\n")
        ingest(bin_path, ws, [x for x in ops_lines if lo <= x[0] < hi], hi,
               ("syslog", "snmp", "nagios", "dhcp", "arp"), os.path.join(wdir, "ops"))
        r = run([bin_path, "beh", "spust", "--workspace", ws, "--nazev", f"w{i}", "--scope", "10.77.0.0/16",
                 "--nmap-xml", nmap, "--zeek-dir", zdir, "--provider", "demo", "--disable-circl"], now=hi)
        if r.returncode != 0:
            out.append({"w": i, "scenario": sid, "phase": phase, "error": True})
            continue
        rep = latest_report(ws)
        finds = {f["finding_id"]: f for f in rep.get("findings", [])}
        shown = []
        for lc in rep.get("findingLifecycle", []):
            f = finds.get(lc["finding_id"], {})
            text = " ".join([str(f.get("title", "")), str(f.get("rationale", "")), str(f.get("host_key", ""))]
                            + [str(e) for e in f.get("evidence", [])])
            d = lc.get("ops_diagnosis") or {}
            shown.append({"type": f.get("finding_type"), "displayed": lc.get("displayed"),
                          "ips": sorted(set(re.findall(r"\b10\.77\.\d{1,3}\.\d{1,3}\b", text))),
                          "class": d.get("class"), "catalog_id": d.get("catalog_id")})
        out.append({"w": i, "scenario": sid, "phase": phase, "slot": rec["slot"], "params": rec.get("params", {}),
                    "flows": sum(1 for ts, _ in zdata["conn"][1] if lo <= ts < hi), "findings": shown})
    return out


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    e = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return (100 * (c - e) / d, 100 * (c + e) / d)


def pct(k, n):
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {100 * k / n:.0f} % ({lo:.0f} až {hi:.0f})" if n else "0/0"


def summarize_m1(res, nod, catalog):
    sig = {e["id"]: {k for k, _ in (e["ops_signals"].items() if isinstance(e["ops_signals"], dict) else e["ops_signals"])}
           for e in catalog["incidents"] if e.get("ops_signals")}
    s = [r for r in res if r["scenario"] in EXPECT]
    c1 = sum(r["class"] == EXPECT[r["scenario"]][0] for r in s)
    c5 = sum(r["class"] == "utok" for r in s)
    delivered = [r for r in s if any(k in r["keys_fault"] for i in EXPECT[r["scenario"]][1] for k in sig.get(i, ()))]
    c2 = sum(r["catalog_id"] in EXPECT[r["scenario"]][1] for r in delivered)
    c2any = sum(r["catalog_id"] in EXPECT[r["scenario"]][1] or bool(set(r["candidates"]) & EXPECT[r["scenario"]][1])
                for r in delivered)
    a = [r for r in res if r["scenario"].startswith("A")]
    c4 = sum(r["class"] != "utok" for r in a)
    c4p = sum(r["class"] in ("porucha", "zmena") for r in a)
    k = [r for r in res if r["scenario"].startswith("K")]
    c6 = sum(r["class"] != "utok" for r in k)
    ns = [r for r in nod if r["scenario"] in EXPECT]
    c3 = sum(r["class"] == "neurceno" for r in ns)
    c3w = sum(r["class"] in ("porucha", "zmena") for r in ns)
    return {"C1": pct(c1, len(s)), "C2": pct(c2, len(delivered)), "C2_kandidat": pct(c2any, len(delivered)),
            "C2_dodano": f"{len(delivered)}/{len(s)}", "C3": pct(c3, len(ns)), "C3_jiste": pct(c3w, len(ns)),
            "C4": pct(c4, len(a)), "C4_porucha_zmena": pct(c4p, len(a)), "C5": pct(c5, len(s)), "C6": f"{c6}/{len(k)}"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-dir", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--skip-m2", action="store_true")
    ap.add_argument("--catalog", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                                      "data", "incident-catalog.json"))
    args = ap.parse_args()
    labels = [json.loads(l) for l in open(os.path.join(args.set_dir, "labels.jsonl"), encoding="utf-8") if l.strip()]
    labels = [l for l in labels if l["slot"] == "warmup" or "fault_end" in l]
    catalog = json.load(open(args.catalog, encoding="utf-8"))
    ops_lines = read_ops(args.set_dir)
    os.makedirs(os.path.join(args.set_dir, "eval"), exist_ok=True)
    summary = {"slots": len(labels) - 1, "ops_lines": Counter(f for _, f, _ in ops_lines)}
    for arm in ARMS:
        res = m1(args.bin, args.set_dir, labels, ops_lines, catalog, arm)
        nod = m1(args.bin, args.set_dir, labels, ops_lines, catalog, arm, nodata=True)
        json.dump({"m1": res, "nodata": nod}, open(os.path.join(args.set_dir, "eval", f"m1-{arm}.json"), "w",
                                                  encoding="utf-8"), indent=1)
        summary[f"M1 {arm}"] = summarize_m1(res, nod, catalog)
    if not args.skip_m2:
        zdata = read_zeek(zeek(args.set_dir))
        summary["zeek_rows"] = {n: len(zdata[n][1]) for n in LOGS}
        for arm in ARMS:
            res = m2(args.bin, args.set_dir, labels, ops_lines, zdata, arm)
            json.dump(res, open(os.path.join(args.set_dir, "eval", f"m2-{arm}.json"), "w", encoding="utf-8"), indent=1)
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
