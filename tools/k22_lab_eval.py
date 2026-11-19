#!/usr/bin/env python3
"""Krok 22, laboratoř C: vyhodnocení produkční cestou se stínovými lístky (impl-krok22.md, 5.3).

Vstup: adresář sady z `tools/k22_lab.py` (labels.jsonl, context-calendar.json, pcap/). Kroky:
1. Zeek na pcap (docker zeek/zeek:9.0.1, `zeek -C -r`), logy do <set>/zeek/.
2. Okna podle fází slotů; pro každé `beh spust --zeek-dir` s `SALTICUS_REPLAY_NOW` = konec okna,
   kalendářem sady ve workspace a `K22_SHADOW` (stín brány i v produkční cestě).
3. Štítky nálezů podle předregistrace: útok A, B, C, D; neškodný se záznamem; ostatní.
Výstup: <set>/eval/ (shadow.jsonl, findings.json, summary.json) a souhrn na stdout.

Pouziti:
  python -I tools/k22_lab_eval.py --set-dir F:/work-tmp/k22/lab/22001 --bin BIN
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

LOGS = ("conn", "dns", "ssl", "x509", "http")
FLAGS = ["memory", "ladder", "context", "protect", "l7_dns", "l7_tls", "close_gate", "ctx_host_first"]
# Inventář laboratoře (znalost operátora ze sestavy labs/k22, ne z výsledků): bez něj produkční
# cesta nezná služby a sken se hlásí jen jako `unmapped_passive_event` bez zdrojů (ladění 22001).
HOSTS = {"10.77.2.10": [(80, "http")], "10.77.2.20": [(445, "microsoft-ds"), (5432, "postgresql")],
         "10.77.2.30": [(445, "microsoft-ds")], "10.77.9.10": [(80, "http")], "10.77.9.9": [(443, "https")],
         "10.77.1.11": [], "10.77.1.12": [], "10.77.1.20": [], "10.77.1.30": [], "10.77.1.40": [],
         "10.77.1.254": [], "10.77.2.254": []}


def inventory_xml():
    out = ['<?xml version="1.0"?>', '<nmaprun scanner="nmap" args="nmap -sV" start="0" version="7.94">']
    for ip, ports in HOSTS.items():
        out.append(f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>')
        for port, name in ports:
            out.append(f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
                       f'<service name="{name}" method="probed" conf="10"/></port>')
        out.append("</ports></host>")
    out.append(f'<runstats><finished time="0"/><hosts up="{len(HOSTS)}" down="0" total="{len(HOSTS)}"/></runstats>')
    out.append("</nmaprun>")
    return "\n".join(out) + "\n"
COVERS = {  # ContextKind::default_covers (src/context_gate.rs)
    "backup": {"inductive_volume_anomaly", "packet_rate_spike", "service_overload_risk", "link_saturation",
               "ingest_volume_anomaly"},
    "batch_job": {"inductive_volume_anomaly", "packet_rate_spike", "service_overload_risk", "link_saturation",
                  "ingest_volume_anomaly"},
    "authorized_scanner": {"scan_attempts", "unexpected_traffic", "connection_timeout_burst",
                           "unmapped_passive_event"},
}
SINK, C1, SCANNER, BACKUP = "10.77.9.9", "10.77.1.11", "10.77.1.30", "10.77.1.20"


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def run(cmd, env_extra, now):
    env = dict(os.environ)
    env.update(env_extra)
    env["SALTICUS_REPLAY_NOW"] = iso(now)
    env["RUST_LOG"] = "error"
    return subprocess.run(cmd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")


def zeek(set_dir):
    out = os.path.join(set_dir, "zeek")
    if os.path.exists(os.path.join(out, "done")):
        return out
    os.makedirs(out, exist_ok=True)
    for pcap in sorted(glob.glob(os.path.join(set_dir, "pcap", "*.pcap"))):
        part = os.path.join(out, os.path.splitext(os.path.basename(pcap))[0])
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


def windows(labels):
    wins = []
    for rec in labels:
        if rec["slot"] == "warmup":
            mid = (rec["start"] + rec["end"]) / 2
            wins += [(rec["start"], mid, None, "warmup"), (mid, rec["end"], None, "warmup")]
            continue
        wins += [(rec["start"], rec["fault_start"], rec, "pre"), (rec["fault_start"], rec["fault_end"], rec, "fault"),
                 (rec["fault_end"], rec["end"], rec, "post")]
    return wins


def latest_report(ws):
    best = max(glob.glob(os.path.join(ws, "runs", "*", "report.json")), key=os.path.getmtime)
    with open(best, encoding="utf-8") as h:
        return json.load(h)


def classify(item, rec, phase):
    """Štítek nálezu podle předregistrace 5.3."""
    ips = set(item["ips"]) | set(item.get("sources", [])) | set(item.get("targets", []))
    if rec is None or phase != "fault":
        return "mimo_ulohu"
    attacks = {a["label"] for a in rec["attacks"]}
    if "A" in attacks and C1 in ips:
        return "utok_A"
    if "B" in attacks and SINK in ips:
        return "utok_B"
    if "C" in attacks and SINK in ips:
        return "utok_C"
    if "D" in attacks and SCANNER in ips:
        return "utok_D_smiseno"
    job = set(rec["job_sources"])
    if job & ips and SINK not in ips and C1 not in ips:
        if rec["recorded"] and item["type"] in COVERS.get(rec["kind"], set()):
            return "neskodny_zaznam"
        if not rec["recorded"] and item["type"] in COVERS.get(rec["kind"], set()):
            return "neskodny_bez_zaznamu"
        return "neskodny_typ_mimo_pokryti"
    return "ostatni"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-dir", required=True)
    ap.add_argument("--bin", required=True)
    args = ap.parse_args()
    sd = args.set_dir
    labels = [json.loads(l) for l in open(os.path.join(sd, "labels.jsonl"), encoding="utf-8") if l.strip()]
    labels = [l for l in labels if l["slot"] == "warmup" or "fault_end" in l]
    zdata = read_zeek(zeek(sd))
    ev = os.path.join(sd, "eval")
    shutil.rmtree(ev, ignore_errors=True)
    ws = os.path.join(ev, "ws")
    os.makedirs(ws)
    with open(os.path.join(ws, "salticus.toml"), "w", encoding="utf-8") as cfg:
        cfg.write('[engine]\nmode = "v3"\n[engine.v3]\n' + "".join(f"{f} = true\n" for f in FLAGS))
    shutil.copy(os.path.join(sd, "context-calendar.json"), os.path.join(ws, "context-calendar.json"))
    nmap = os.path.join(ev, "inventory-nmap.xml")
    with open(nmap, "w", encoding="utf-8") as h:
        h.write(inventory_xml())
    shadow_path = os.path.join(ev, "shadow.jsonl")
    findings = []
    for i, (lo, hi, rec, phase) in enumerate(windows(labels)):
        zdir = os.path.join(ev, "win", f"w{i:03d}")
        os.makedirs(zdir, exist_ok=True)
        for n in LOGS:
            head, rows = zdata[n]
            sel = [line for ts, line in rows if lo <= ts < hi]
            if sel:
                with open(os.path.join(zdir, n + ".log"), "w", encoding="utf-8", newline="\n") as h:
                    h.write("\n".join(head) + "\n" + "\n".join(sel) + "\n")
        before = sum(1 for _ in open(shadow_path, encoding="utf-8")) if os.path.exists(shadow_path) else 0
        r = run([args.bin, "beh", "spust", "--workspace", ws, "--nazev", f"w{i}", "--scope", "10.77.0.0/16",
                 "--nmap-xml", nmap, "--zeek-dir", zdir, "--provider", "demo", "--disable-circl"],
                {"K22_SHADOW": shadow_path}, hi)
        if r.returncode != 0:
            sys.stderr.write(f"w{i} chyba: {r.stderr[-400:]}\n")
            continue
        shadows = {}
        if os.path.exists(shadow_path):
            with open(shadow_path, encoding="utf-8") as h:
                for line in list(h)[before:]:
                    s = json.loads(line)
                    shadows.setdefault(s["id"], []).append(s)
        rep = latest_report(ws)
        finds = {f["finding_id"]: f for f in rep.get("findings", [])}
        for lc in rep.get("findingLifecycle", []):
            f = finds.get(lc["finding_id"], {})
            text = " ".join([str(f.get("title", "")), str(f.get("rationale", "")), str(f.get("host_key", "")),
                             str(f.get("service_key", ""))] + [str(e) for e in f.get("evidence", [])])
            sh = shadows.get(lc["finding_id"], [])
            item = {"w": i, "phase": phase, "slot": rec["slot"] if rec else None,
                    "scenario": rec["scenario"] if rec else "warmup", "id": lc["finding_id"],
                    "type": f.get("finding_type"), "displayed": lc.get("displayed"), "state": lc.get("state"),
                    "ips": sorted(set(re.findall(r"\b10\.77\.\d{1,3}\.\d{1,3}\b", text))),
                    "sources": sorted({x for s in sh for x in s.get("sources", [])}),
                    "targets": sorted({x for s in sh for x in s.get("targets", [])}),
                    "shadow": [{"ev": s["ev"], "kind": s.get("kind"), "admitted": s["shadow"]["admitted"],
                                "refusal": s["shadow"].get("refusal")} for s in sh]}
            item["label"] = classify(item, rec, phase)
            item["ticket"] = any(s["admitted"] for s in item["shadow"])
            findings.append(item)
    by = defaultdict(Counter)
    for f in findings:
        by[f["label"]]["n"] += 1
        by[f["label"]]["ticket"] += f["ticket"]
        by[f["label"]]["explained"] += any(s["ev"] == "context" for s in f["shadow"])
    per_slot = defaultdict(Counter)
    for f in findings:
        if f["phase"] == "fault":
            per_slot[f["scenario"]][f"{f['label']}|{'listek' if f['ticket'] else 'bez'}"] += 1
    summary = {"windows": len(windows(labels)), "findings": len(findings),
               "zeek_conn": len(zdata["conn"][1]),
               "labels": {k: dict(v) for k, v in by.items()},
               "per_slot": {k: dict(v) for k, v in sorted(per_slot.items())},
               "types_fault": dict(Counter(f"{f['scenario'][:2]}|{f['type']}" for f in findings
                                           if f["phase"] == "fault"))}
    with open(os.path.join(ev, "findings.json"), "w", encoding="utf-8") as h:
        json.dump(findings, h, indent=1)
    with open(os.path.join(ev, "summary.json"), "w", encoding="utf-8") as h:
        json.dump(summary, h, indent=1, ensure_ascii=False)
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
