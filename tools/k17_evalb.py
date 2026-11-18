#!/usr/bin/env python3
"""Krok 17, laboratoř B: detekce DNS tunelu a DoH produkční cestou (impl-krok17.md, T1 až T3, D1).

Pro každou relaci (pcap z `tools/k17_labb.py`): Zeek (`zeek -C -r`), pak jedno `beh spust
--zeek-dir` se `l7_dns,l7_tls` a rozsahem sítě klientů 10.88.1.0/24 (servery laboratoře jsou
pro klienta „venku“, dodatek D1). Zjistí nálezy `dns_tunnel_names`, `dns_zone_enumeration`
a `doh_suspected` (vytvořené i zobrazené). Tunely a DoH jsou pozitivní relace, kontroly
negativní (jakýkoli z těchto nálezů = falešný poplach). Navíc z Zeek dns.log a conn.log
vypíše rysy (tvar jmen v2, tvar toků na 443), aby bylo vidět, proč detektor zabral nebo ne.

Pouziti:
  python -I tools/k17_evalb.py --set-dir F:/Projekty/bakula-datasets/lab-k17/debugB --bin BIN
"""
import argparse
import glob
import json
import math
import os
import subprocess
import sys
from collections import Counter, defaultdict

EMPTY_NMAP = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="replay" start="0" version="7.94">
<runstats><finished time="0"/><hosts up="0" down="0" total="0"/></runstats>
</nmaprun>
"""
COVERT_TYPES = {"dns_tunnel_names", "dns_zone_enumeration", "doh_suspected"}
DATA_TYPES = {"TXT", "NULL", "PRIVATE", "CNAME", "MX", "SRV", "KEY", "DNAME"}
SCOPE = "10.88.1.0/24"


def category(mode):
    if mode.startswith("control"):
        return "control"
    if mode.startswith("doh"):
        return "doh"
    return "tunnel"


def family(mode):
    for f in ("iodine", "dnscat", "dns2tcp", "exfil", "doh", "control"):
        if mode.startswith(f):
            return f
    return mode


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(max(0.0, c - h), 3), round(min(1.0, c + h), 3))


def zeek(pcap, out):
    os.makedirs(out, exist_ok=True)
    if not os.path.exists(os.path.join(out, "conn.log")):
        subprocess.run(["docker", "run", "--rm", "-v", f"{os.path.dirname(pcap)}:/pcap:ro", "-v", f"{out}:/out",
                        "-w", "/out", "zeek/zeek:9.0.1", "zeek", "-C", "-r", f"/pcap/{os.path.basename(pcap)}"],
                       capture_output=True, check=False)
    return out


def rows(path):
    if not os.path.exists(path):
        return []
    cols, out = None, []
    with open(path, encoding="utf-8", errors="replace") as h:
        for line in h:
            if line.startswith("#fields"):
                cols = line.rstrip("\n").split("\t")[1:]
            elif not line.startswith("#") and cols and line.strip():
                out.append(dict(zip(cols, line.rstrip("\n").split("\t"))))
    return out


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum((v / len(s)) * math.log2(v / len(s)) for v in c.values())


def dns_shape(zdir):
    """Rysy v2 po (zdroj, zóna) přes různá jména; jen skupiny s ≥ 5 dotazy."""
    by = defaultdict(lambda: {"names": set(), "q": 0, "typed": 0, "ts": []})
    for r in rows(os.path.join(zdir, "dns.log")):
        q = r.get("query", "-").lower().rstrip(".")
        if q in ("-", "") or q.endswith(".local") or r.get("id.resp_h") in ("224.0.0.251", "ff02::fb"):
            continue
        parts = q.split(".")
        zone = ".".join(parts[-2:]) if len(parts) >= 2 else q
        g = by[(r.get("id.orig_h"), zone)]
        g["names"].add(q)
        g["q"] += 1
        g["typed"] += r.get("qtype_name") in DATA_TYPES
        try:
            g["ts"].append(float(r.get("ts")))
        except (TypeError, ValueError):
            pass
    out = {}
    for (src, zone), g in by.items():
        if g["q"] < 5:
            continue
        enc = [n[: -len(zone)].rstrip(".").replace(".", "") for n in g["names"]]
        b = sum(len(e) for e in enc)
        span = max(60.0, (max(g["ts"]) - min(g["ts"])) if g["ts"] else 0.0)
        out[f"{src} {zone}"] = {"names": len(g["names"]), "queries": g["q"],
                                "uniq": round(len(g["names"]) / g["q"], 2),
                                "avg_len": round(b / len(enc), 1), "avg_entropy": round(sum(map(entropy, enc)) / len(enc), 2),
                                "data_types": round(g["typed"] / g["q"], 2), "bytes": b, "rate": round(b / span, 1)}
    return out


def tls_shape(zdir):
    """Tvar toků TCP/443 po cíli: počet, mediány bajtů a trvání, nejdelší spojení."""
    per = defaultdict(list)
    for r in rows(os.path.join(zdir, "conn.log")):
        if r.get("proto") == "tcp" and r.get("id.resp_p") in ("443", "853"):
            per[r["id.resp_h"]].append(r)

    def num(x):
        try:
            return float(x)
        except (TypeError, ValueError):
            return 0.0

    def med(v):
        v = sorted(v)
        return v[len(v) // 2] if v else 0

    out = {}
    for dst, fl in per.items():
        longest = max(fl, key=lambda r: num(r.get("duration")))
        out[dst] = {"conns": len(fl), "med_up": med([num(r.get("orig_bytes")) for r in fl]),
                    "med_down": med([num(r.get("resp_bytes")) for r in fl]),
                    "med_dur": round(med([num(r.get("duration")) for r in fl]), 3),
                    "longest_s": round(num(longest.get("duration")), 1), "longest_pkts": int(num(longest.get("orig_pkts")))}
    return out


def run_detect(binp, set_dir, zdir, label):
    ws = os.path.join(set_dir, "eval", "ws-" + label)
    os.makedirs(os.path.join(ws, "runs"), exist_ok=True)
    with open(os.path.join(ws, "salticus.toml"), "w", encoding="utf-8") as c:
        c.write('[engine]\nmode = "v3"\n[engine.v3]\nprotect = true\nl7_dns = true\nl7_tls = true\n')
    nmap = os.path.join(set_dir, "eval", "empty.xml")
    os.makedirs(os.path.dirname(nmap), exist_ok=True)
    with open(nmap, "w", encoding="utf-8") as h:
        h.write(EMPTY_NMAP)
    env = dict(os.environ, RUST_LOG="error")
    r = subprocess.run([binp, "beh", "spust", "--workspace", ws, "--nazev", label, "--scope", SCOPE,
                        "--nmap-xml", nmap, "--zeek-dir", zdir, "--provider", "demo", "--disable-circl"],
                       capture_output=True, text=True, env=env, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        return {"error": r.stderr[-400:]}
    best = max(glob.glob(os.path.join(ws, "runs", "*", "report.json")), key=os.path.getmtime)
    with open(best, encoding="utf-8") as h:
        rep = json.load(h)
    finds = {f["finding_id"]: f for f in rep.get("findings", [])}
    covert, other = [], Counter()
    for lc in rep.get("findingLifecycle", []):
        f = finds.get(lc["finding_id"], {})
        if f.get("finding_type") in COVERT_TYPES:
            covert.append({"type": f.get("finding_type"), "displayed": bool(lc.get("displayed")),
                           "title": str(f.get("title", ""))[:160]})
        elif lc.get("displayed"):
            other[f.get("finding_type")] += 1
    return {"covert": covert, "other_displayed": dict(other), "n_findings": len(rep.get("findings", []))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set-dir", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--fresh", action="store_true", help="smazat pracovní prostory detekce (Zeek logy zůstanou)")
    args = ap.parse_args()
    with open(os.path.join(args.set_dir, "labels.jsonl"), encoding="utf-8") as h:
        labels = [json.loads(line) for line in h if line.strip()]
    per_mode = defaultdict(lambda: [0, 0])
    per_cat = defaultdict(lambda: [0, 0])
    fp, controls = 0, 0
    details = []
    for rec in labels:
        if "pcap" not in rec:
            details.append({"relation": rec.get("relation"), "error": rec.get("error")})
            continue
        label, mode = rec["relation"], rec["mode"]
        pcap = os.path.join(args.set_dir, rec["pcap"])
        if not os.path.exists(pcap):
            details.append({"relation": label, "error": "pcap chybí"})
            continue
        if args.fresh:
            subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", os.path.join(args.set_dir, "eval", "ws-" + label)],
                           capture_output=True)
        zdir = zeek(pcap, os.path.join(args.set_dir, "eval", "zeek-" + label))
        det = run_detect(args.bin, args.set_dir, zdir, label)
        cov = det.get("covert", [])
        cat = category(mode)
        if cat == "tunnel":
            hit = any(c["type"] in ("dns_tunnel_names", "dns_zone_enumeration") for c in cov)
        elif cat == "doh":
            hit = any(c["type"] == "doh_suspected" for c in cov)
        else:
            hit = bool(cov)
            controls += 1
            fp += hit
        per_mode[mode][0] += hit
        per_mode[mode][1] += 1
        if cat != "control":
            per_cat[family(mode)][0] += hit
            per_cat[family(mode)][1] += 1
            per_cat[cat][0] += hit
            per_cat[cat][1] += 1
        details.append({"relation": label, "mode": mode, "category": cat, "hit": hit,
                        "covert": cov, "other_displayed": det.get("other_displayed"),
                        "dns_shape": dns_shape(zdir), "tls_shape": tls_shape(zdir),
                        "n_findings": det.get("n_findings"), "error": det.get("error")})
    summary = {
        "per_mode": {m: f"{k}/{n}" for m, (k, n) in sorted(per_mode.items())},
        "per_family": {m: {"k": k, "n": n, "wilson95": wilson(k, n)} for m, (k, n) in sorted(per_cat.items())},
        "false_positives_controls": f"{fp}/{controls}", "fp_wilson95": wilson(fp, controls),
        "detaily": details,
    }
    with open(os.path.join(args.set_dir, "eval", "covert.json"), "w", encoding="utf-8") as h:
        json.dump(summary, h, ensure_ascii=False, indent=1)
    sys.stdout.reconfigure(encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "detaily"}, ensure_ascii=False, indent=1))
    for d in details:
        tag = "OK " if (d.get("hit") and d.get("category") != "control") or (not d.get("hit") and d.get("category") == "control") else "XX "
        print(tag, d.get("relation"), [c["type"] + ("*" if c["displayed"] else "") for c in d.get("covert", [])], d.get("error") or "")


if __name__ == "__main__":
    main()
