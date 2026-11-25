#!/usr/bin/env python3
"""Krok 40: korelace na Unraveled/DAPT2021 (APT s pravdou po fázích na úrovni toků).

  k40_dapt.py convert --dir DEN_s_csv --out conn.log --truth truth.json
  k40_dapt.py run  --conn conn.log --bin salticus-program.exe --work DIR [--v3-on ...]
  k40_dapt.py eval --result DIR/result.json --truth truth.json

Vstup: NFStream CSV po snímačích (net101xx a netgw) s poli Activity, Stage, DefenderResponse,
Signature. `convert` spojí snímače, odstraní duplicitní toky a zapíše Zeek-like `conn.log`;
`truth.json` nese adresy a časové intervaly fází kampaně `APT` (Signature). Ostatní útoky (AA, SH)
se do kampaně nepočítají a nálezy, které zmiňují jen jejich adresy, se z kontaminace vynechají.
"""
import argparse
import csv
import glob
import importlib.util
import json
import os
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


k33 = load("k33_corr")
k35 = load("k35_corr")
FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes "
          "resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts "
          "orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents ip_proto").split()


def cmd_convert(a):
    seen, rows = set(), []
    stages = defaultdict(lambda: [1e18, 0.0])
    camp_ips, other_ips = set(), set()
    n_in = 0
    for path in sorted(glob.glob(os.path.join(a.dir, "*.csv"))):
        rd = csv.reader(open(path, encoding="utf-8", errors="replace"))
        h = next(rd)
        ix = {n: k for k, n in enumerate(h)}
        for r in rd:
            if len(r) != len(h):
                continue
            n_in += 1
            key = (r[ix["src_ip"]], r[ix["src_port"]], r[ix["dst_ip"]], r[ix["dst_port"]],
                   r[ix["protocol"]], r[ix["bidirectional_first_seen_ms"]])
            if key in seen:
                continue
            seen.add(key)
            ts = int(r[ix["bidirectional_first_seen_ms"]]) / 1000.0
            dur = int(r[ix["bidirectional_duration_ms"]]) / 1000.0
            proto_n = r[ix["protocol"]]
            proto = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto_n, "tcp")
            sp, dp = int(r[ix["src2dst_packets"]]), int(r[ix["dst2src_packets"]])
            if proto == "tcp":
                rst = int(r[ix["bidirectional_rst_packets"]])
                state = "S0" if dp == 0 else ("RSTO" if rst > 0 and int(r[ix["bidirectional_fin_packets"]]) == 0 else "SF")
            else:
                state = "S0" if dp == 0 else "SF"
            sig, stage = r[-1], r[-3]
            if sig != "None":
                if sig == "APT":
                    camp_ips.update([r[ix["src_ip"]], r[ix["dst_ip"]]])
                    s = stages[stage]
                    s[0], s[1] = min(s[0], ts), max(s[1], ts + dur)
                else:
                    other_ips.update([r[ix["src_ip"]], r[ix["dst_ip"]]])
            uid = f"C{len(rows):012d}"
            rows.append((ts, [f"{ts:.6f}", uid, r[ix["src_ip"]], r[ix["src_port"]], r[ix["dst_ip"]],
                              r[ix["dst_port"]], proto, "-", f"{dur:.6f}", r[ix["src2dst_bytes"]],
                              r[ix["dst2src_bytes"]], state, "T", "T", "0", "-", str(sp),
                              r[ix["src2dst_bytes"]], str(dp), r[ix["dst2src_bytes"]], "-",
                              proto_n if proto_n in ("6", "17", "1") else "6"]))
    rows.sort(key=lambda x: x[0])
    with open(a.out, "w", encoding="utf-8", newline="\n") as out:
        out.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        out.write("#fields\t" + "\t".join(FIELDS) + "\n")
        for _, r in rows:
            out.write("\t".join(r) + "\n")
    json.dump({"campaign_ips": sorted(camp_ips), "other_attack_ips": sorted(other_ips - camp_ips),
               "stages": {k: v for k, v in stages.items()}}, open(a.truth, "w"), indent=1)
    print(f"toku vstup {n_in}, po odstraneni duplicit {len(rows)}, kampan {sorted(camp_ips)}, faze {dict(stages)}")


def evaluate(res, truth, window=1800):
    camp, other = set(truth["campaign_ips"]), set(truth["other_attack_ips"])
    stages = truth["stages"]
    t_lo = min(v[0] for v in stages.values()) - window
    t_hi = max(v[1] for v in stages.values()) + window
    shown = {f["id"]: f for f in res["shown"]}

    def level(fid):
        f = shown[fid]
        m = k33.ips_of(f["text"])
        if not m & camp:
            return "other" if m & other else None
        lv = "loose"
        if t_lo <= f["t"] <= t_hi:
            lv = "normal"
            if any(a - window <= f["t"] <= b + window for a, b in stages.values()):
                lv = "strict"
        return lv
    lev = {i: level(i) for i in shown}
    rank = {"loose": 0, "normal": 1, "strict": 2}
    out = {"campaign_ips": sorted(camp), "shown": len(shown),
           "by_level": {lv: sum(1 for v in lev.values() if v in rank and rank[v] >= rank[lv]) for lv in rank},
           "other_attack_findings": sum(1 for v in lev.values() if v == "other"), "arms": {}}
    inc = res["incidents"]
    idx = {i.get("key"): n for n, i in enumerate(inc)}
    parent = list(range(len(inc)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for n, i in enumerate(inc):
        for r in i.get("related", []):
            if r["key"] in idx:
                parent[find(n)] = find(idx[r["key"]])
    clo = defaultdict(list)
    for n, i in enumerate(inc):
        clo[find(n)].extend(i["findings"])
    arms = {"B1": k33.groups_ip(res["shown"]), "B1b": k35.groups_ip_window(res["shown"]),
            "INC": [i["findings"] for i in inc], "INC_closure": list(clo.values())}
    for lv in rank:
        chain = {i for i, v in lev.items() if v in rank and rank[v] >= rank[lv]}
        for name, groups in arms.items():
            groups = [g for g in groups if len(g) >= 2]
            ci = [g for g in groups if any(f in chain for f in g)]
            in_ci = sum(len(g) for g in ci)
            non = sum(1 for g in ci for f in g if f not in chain and lev.get(f) != "other")
            hosts = lambda g: {x for f in g if f in chain for x in k33.ips_of(shown[f]["text"]) & camp}
            best = max(ci, key=lambda g: len(hosts(g)), default=[])
            out["arms"].setdefault(lv, {})[name] = {
                "incidents_total": len(groups), "chain_incidents": len(ci),
                "completeness": max((sum(1 for f in g if f in chain) for g in ci), default=0) / len(chain) if chain else 0,
                "campaign_hosts_in_best": len(hosts(best)),
                "contamination": non / in_ci if in_ci else 0.0,
                "largest_incident": max((len(g) for g in groups), default=0)}
    return out


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("convert")
    c.add_argument("--dir", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--truth", required=True)
    r = sub.add_parser("run")
    r.add_argument("--conn", required=True)
    r.add_argument("--bin", required=True)
    r.add_argument("--work", required=True)
    r.add_argument("--scope", default="10.0.0.0/8")
    r.add_argument("--window", type=int, default=1800)
    r.add_argument("--v3-on", default="")
    r.add_argument("--env", action="append", default=[])
    e = sub.add_parser("eval")
    e.add_argument("--result", required=True)
    e.add_argument("--truth", required=True)
    a = ap.parse_args()
    if a.cmd == "convert":
        cmd_convert(a)
    elif a.cmd == "run":
        k33.cmd_run(a)
    else:
        print(json.dumps(evaluate(json.load(open(a.result, encoding="utf-8")),
                                  json.load(open(a.truth, encoding="utf-8"))),
                         indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
