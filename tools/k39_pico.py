#!/usr/bin/env python3
"""Krok 39: korelace na PicoDomain (skutečná vícehostitelská APT kampaň, 3 dny, Zeek JSON).

  k39_pico.py convert --zeek DIR_s_datumy --out conn.log
  k39_pico.py run  --conn conn.log --bin salticus-program.exe --work DIR [--v3-on ...]
  k39_pico.py eval --result DIR/result.json --redlog RedLog.xlsx

Pravda: `Red Log.xlsx` (čas UTC, hostitel oběti, akce; ručně zapsáno s přesností asi 1 minuta) a
list `Normal User Workstations` (hostitel -> IP). Kampaň = IP hostitelů z červeného logu plus C2
3.3.3.5. Tři úrovně označení nálezu: loose (zmiňuje adresu kampaně), normal (navíc v čase
kampaně ±30 min), strict (zmiňuje IP hostitele řádku logu a je ±30 min od jeho času).
"""
import argparse
import glob
import importlib.util
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


k33 = load("k33_corr")
k35 = load("k35_corr")
C2 = "3.3.3.5"
FIELDS = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes "
          "resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts "
          "orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents ip_proto").split()


def cmd_convert(a):
    rows = []
    for path in sorted(glob.glob(os.path.join(a.zeek, "*", "conn.*.log"))):
        for line in open(path, encoding="utf-8", errors="replace"):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            ts = datetime.fromisoformat(d["ts"].replace("Z", "+00:00")).timestamp()
            def g(k, default="-"):
                v = d.get(k)
                if v is None:
                    return default
                if isinstance(v, bool):
                    return "T" if v else "F"
                return str(v)
            proto = d.get("proto", "tcp")
            rows.append((ts, [f"{ts:.6f}", g("uid"), g("id.orig_h"), g("id.orig_p"), g("id.resp_h"),
                              g("id.resp_p"), proto, g("service"), g("duration"), g("orig_bytes"),
                              g("resp_bytes"), g("conn_state"), g("local_orig"), g("local_resp"),
                              g("missed_bytes", "0"), g("history"), g("orig_pkts"),
                              g("orig_ip_bytes"), g("resp_pkts"), g("resp_ip_bytes"), "-",
                              "6" if proto == "tcp" else ("17" if proto == "udp" else "1")]))
    rows.sort(key=lambda r: r[0])
    with open(a.out, "w", encoding="utf-8", newline="\n") as out:
        out.write("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        out.write("#fields\t" + "\t".join(FIELDS) + "\n")
        for _, r in rows:
            out.write("\t".join(r) + "\n")
    print(f"toku {len(rows)}")


def red_truth(path):
    import openpyxl
    wb = openpyxl.load_workbook(path)
    ips = {}
    for r in wb["Normal User Workstations"].iter_rows(min_row=2, values_only=True):
        if r[0] and r[1]:
            ips[r[0].upper()] = r[1]
    events, day = [], None
    for r in wb["Red Activity"].iter_rows(min_row=2, values_only=True):
        if isinstance(r[0], datetime):
            day = r[0].date()
            continue
        if r[0] is None or r[1] is None or day is None:
            continue
        t = datetime.combine(day, r[0]).replace(tzinfo=timezone.utc).timestamp()
        ip = ips.get(str(r[1]).upper())
        if ip:
            events.append({"t": t, "host": str(r[1]), "ip": ip, "action": str(r[4])})
    return ips, events


def evaluate(res, redlog, window=1800):
    ips, events = red_truth(redlog)
    camp = {e["ip"] for e in events} | {C2}
    t_lo = min(e["t"] for e in events) - window
    t_hi = max(e["t"] for e in events) + window
    shown = {f["id"]: f for f in res["shown"]}

    def level(fid):
        f = shown[fid]
        m = k33.ips_of(f["text"]) & camp
        if not m:
            return None
        lv = "loose"
        if t_lo <= f["t"] <= t_hi:
            lv = "normal"
            for e in events:
                if e["ip"] in m and abs(f["t"] - e["t"]) <= window:
                    lv = "strict"
                    break
        return lv
    lev = {i: level(i) for i in shown}
    rank = {"loose": 0, "normal": 1, "strict": 2}
    out = {"campaign_ips": sorted(camp), "shown": len(shown), "red_events": len(events),
           "by_level": {lv: sum(1 for v in lev.values() if v and rank[v] >= rank[lv]) for lv in rank},
           "arms": {}}
    arms = {"B1": k33.groups_ip(res["shown"]), "B1b": k35.groups_ip_window(res["shown"]),
            "INC": [i["findings"] for i in res["incidents"]]}
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
    arms["INC_closure"] = list(clo.values())
    for lv in rank:
        chain = {i for i, v in lev.items() if v and rank[v] >= rank[lv]}
        for name, groups in arms.items():
            groups = [g for g in groups if len(g) >= 2]
            ci = [g for g in groups if any(f in chain for f in g)]
            in_ci = sum(len(g) for g in ci)
            non = sum(1 for g in ci for f in g if f not in chain)
            hosts = lambda g: {x for f in g if f in chain for x in k33.ips_of(shown[f]["text"]) & camp} - {C2}
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
    c.add_argument("--zeek", required=True)
    c.add_argument("--out", required=True)
    r = sub.add_parser("run")
    r.add_argument("--conn", required=True)
    r.add_argument("--bin", required=True)
    r.add_argument("--work", required=True)
    r.add_argument("--scope", default="10.99.99.0/24")
    r.add_argument("--window", type=int, default=1800)
    r.add_argument("--v3-on", default="")
    r.add_argument("--env", action="append", default=[])
    e = sub.add_parser("eval")
    e.add_argument("--result", required=True)
    e.add_argument("--redlog", required=True)
    a = ap.parse_args()
    if a.cmd == "convert":
        cmd_convert(a)
    elif a.cmd == "run":
        k33.cmd_run(a)
    else:
        print(json.dumps(evaluate(json.load(open(a.result, encoding="utf-8")), a.redlog),
                         indent=1, ensure_ascii=False))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
