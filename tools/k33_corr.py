#!/usr/bin/env python3
"""Krok 33: přehrání vícefázových řetězců po oknech a vyhodnocení korelace.

  k33_corr.py run  --conn zeek_chain/conn.log --bin salticus-program.exe --work DIR
                   [--v3-on attempts,case_files,...] [--env K=V]   -> DIR/result.json
  k33_corr.py eval --result DIR/result.json --truth truth_chain.json [--seed N]

`run` uloží zobrazené nálezy (finding_id, text, čas prvního výskytu) a incidenty z posledního
reportu. `eval` z nich spočítá metriky pro ramena (nálezy jsou stejné, mění se jen seskupení):
  B0 každý nález sám, B1 podle sdílené IP, B2 náhodné seskupení se stejnými velikostmi jako B1,
  B3/B4 incidenty z produkce (v1 / v2 podle toho, s jakým přepínačem běh proběhl).
"""
import argparse
import importlib.util
import json
import os
import random
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


replay = load("replay_public")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def cmd_run(a):
    fields, rows = replay.read_conn(a.conn)
    t0 = rows[0]["_ts"]
    windows = defaultdict(list)
    for r in rows:
        windows[int((r["_ts"] - t0) // a.window)].append(r)
    workspace = os.path.join(a.work, "ws")
    os.makedirs(workspace, exist_ok=True)
    with open(os.path.join(workspace, "salticus.toml"), "w", encoding="utf-8") as cfg:
        cfg.write('[engine]\nmode = "v3"\n')
        extra = [n.strip() for n in a.v3_on.split(",") if n.strip()]
        if extra:
            cfg.write("[engine.v3]\n")
            for n in extra:
                cfg.write(f"{n} = true\n")
    nmap = os.path.join(a.work, "empty-nmap.xml")
    with open(nmap, "w", encoding="utf-8") as h:
        h.write(replay.EMPTY_NMAP)
    shown = {}
    last = {}
    snapshots = []
    failures = 0
    order = sorted(windows)
    for n, index in enumerate(order):
        start = t0 + index * a.window
        wdir = os.path.join(a.work, "w", "zeek")
        replay.write_window(wdir, fields, windows[index])
        env = dict(os.environ)
        for kv in a.env:
            k, v = kv.split("=", 1)
            env[k] = v
        env["SALTICUS_REPLAY_NOW"] = datetime.fromtimestamp(start, timezone.utc).isoformat()
        cmd = [a.bin, "beh", "spust", "--workspace", workspace, "--nazev", f"w{index}",
               "--scope", a.scope, "--nmap-xml", nmap, "--zeek-dir", wdir,
               "--provider", "demo", "--disable-circl"]
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode != 0:
            failures += 1
            sys.stderr.write(proc.stderr[-800:])
            continue
        report = replay.latest_report(workspace)
        findings = {f["finding_id"]: f for f in report.get("findings", [])}
        for rec in report.get("findingLifecycle", []):
            if not rec.get("displayed"):
                continue
            f = findings.get(rec["finding_id"], {})
            fid = rec["finding_id"]
            if fid not in shown:
                shown[fid] = {"id": fid, "type": f.get("finding_type"), "severity": f.get("severity"),
                              "t": start, "text": json.dumps(f, ensure_ascii=False)}
        last = report.get("correlation") or {}
        snapshots.append({"t": start, "incidents": [
            {"key": i.get("key", ""), "findings": i.get("findings", [])}
            for i in last.get("incidents", [])]})
        runs = os.path.join(workspace, "runs")
        for old in sorted(os.listdir(runs))[:-3]:
            if old.startswith("run-"):
                shutil.rmtree(os.path.join(runs, old), ignore_errors=True)
        if n % 10 == 0:
            print(f"okno {n}/{len(order)} zobrazeno {len(shown)}", flush=True)
    json.dump({"windows": len(order), "failures": failures, "t0": t0, "window": a.window,
               "shown": list(shown.values()), "incidents": last.get("incidents", []),
               "stats": last.get("stats", {}), "snapshots": snapshots},
              open(os.path.join(a.work, "result.json"), "w", encoding="utf-8"))
    print(f"hotovo: okna {len(order)}, selhani {failures}, zobrazeno {len(shown)}, "
          f"incidentu {len(last.get('incidents', []))}")


# ----------------------------------------------------------------- vyhodnocení

def ips_of(text):
    return set(IP_RE.findall(text))


def chain_of(text, truth):
    """Nález patří řetězci, jen když zmiňuje IP jednoznačného aktéra fáze (útočník, oběť,
    pivot); sdílené adresy (vnější X, obětní server S) řetězec neurčují."""
    ips = ips_of(text)
    hit = set()
    for c in truth:
        own = set(c["ips"])
        if own & ips:
            hit.add(c["chain"])
    return hit


def groups_ip(findings):
    """B1: spojení nálezů, které sdílejí aspoň jednu IP (union-find)."""
    parent = list(range(len(findings)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    by_ip = {}
    for i, f in enumerate(findings):
        for ip in ips_of(f["text"]):
            if ip in by_ip:
                parent[find(i)] = find(by_ip[ip])
            else:
                by_ip[ip] = i
    out = defaultdict(list)
    for i in range(len(findings)):
        out[find(i)].append(findings[i]["id"])
    return list(out.values())


def metrics(groups, truth, label_of):
    """groups: seznam seznamů finding_id. label_of: finding_id -> množina řetězců."""
    g_of = {}
    for gi, g in enumerate(groups):
        for fid in g:
            g_of.setdefault(fid, set()).add(gi)
    purity, merged = [], 0
    mapped_groups = 0
    for g in groups:
        labs = [next(iter(label_of[f])) for f in g if len(label_of.get(f, ())) == 1]
        if len(labs) >= 2:
            mapped_groups += 1
            top = max(set(labs), key=labs.count)
            purity.append(labs.count(top) / len(labs))
            if len(set(labs)) > 1:
                merged += 1
    frag, complete = [], []
    for c in truth:
        fs = [f for f, ls in label_of.items() if ls == {c["chain"]}]
        if not fs:
            continue
        gs = set()
        for f in fs:
            gs |= g_of.get(f, set())
        frag.append(len(gs))
        best = max((sum(1 for f in fs if gi in g_of.get(f, ())) for gi in gs), default=0)
        complete.append(best / len(fs))
    # B-cubed F1 přes dvojice nálezů stejného řetězce (a jen z různých fází = všechny dvojice,
    # protože nález je jedna fáze; dvojice jsou tedy z definice mezifázové)
    tp = fp = fn = 0
    ids = [f for f, ls in label_of.items() if len(ls) == 1]
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            same_chain = label_of[ids[i]] == label_of[ids[j]]
            same_group = bool(g_of.get(ids[i], set()) & g_of.get(ids[j], set()))
            if same_chain and same_group:
                tp += 1
            elif same_group:
                fp += 1
            elif same_chain:
                fn += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"groups": len(groups), "mapped_groups": mapped_groups,
            "purity_mean": sum(purity) / len(purity) if purity else None,
            "merged_groups": merged,
            "fragmentation_mean": sum(frag) / len(frag) if frag else None,
            "completeness_mean": sum(complete) / len(complete) if complete else None,
            "pair_precision": prec, "pair_recall": rec, "pair_f1": f1,
            "pairs": {"tp": tp, "fp": fp, "fn": fn}}


def pair_stats(groups, label_of):
    """Počty dvojic nálezů s jednoznačným řetězcem: N[c] všech dvojic uvnitř řetězce, S[c] ve
    stejné skupině uvnitř řetězce, W[(c,d)] ve stejné skupině mezi různými řetězci, n[c] počet."""
    n, S, W = defaultdict(int), defaultdict(int), defaultdict(int)
    single = {f: next(iter(ls)) for f, ls in label_of.items() if len(ls) == 1}
    for f, c in single.items():
        n[c] += 1
    N = {c: k * (k - 1) // 2 for c, k in n.items()}
    for g in groups:
        ids = [f for f in g if f in single]
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                c, d = single[ids[i]], single[ids[j]]
                if c == d:
                    S[c] += 1
                else:
                    W[tuple(sorted((c, d)))] += 1
    return n, N, S, W


def boot_f1(n, N, S, W, mult):
    """Párové F1 pro vzorek řetězců s násobností `mult` (kopie téhož řetězce jsou různé řetězce)."""
    tp = fp = fn = 0.0
    for c, m in mult.items():
        if m == 0 or c not in n:
            continue
        tp += m * S.get(c, 0)
        fn += m * (N[c] - S.get(c, 0))
        fp += m * (m - 1) * S.get(c, 0)           # stejná dvojice mezi dvěma kopiemi
        fp += n[c] * m * (m - 1) / 2              # tentýž nález v různých kopiích
    for (c, d), w in W.items():
        fp += mult.get(c, 0) * mult.get(d, 0) * w
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return 2 * prec * rec / (prec + rec) if prec + rec else 0.0


def bootstrap(truth, arms_stats, n_boot=2000, seed=11):
    """Paired bootstrap přes řetězce; vrací intervaly F1 ramen a rozdílů proti B1."""
    rng = random.Random(seed)
    ids = [c["chain"] for c in truth]
    sims = {k: [] for k in arms_stats}
    diffs = {k: [] for k in arms_stats}
    for _ in range(n_boot):
        mult = defaultdict(int)
        for _ in ids:
            mult[rng.choice(ids)] += 1
        f1 = {k: boot_f1(*st, mult) for k, st in arms_stats.items()}
        for k in arms_stats:
            sims[k].append(f1[k])
            diffs[k].append(f1[k] - f1["B1_ip"])
    def ci(v):
        v = sorted(v)
        return [round(v[int(0.025 * len(v))], 3), round(v[int(0.975 * len(v)) - 1], 3)]
    return {k: {"f1_ci": ci(sims[k]), "diff_vs_B1_ci": ci(diffs[k])} for k in arms_stats}


def cluster_bootstrap(truth, arms_stats, n_boot=2000, seed=11):
    """Bootstrap přes jednotky pravdy (samostatný řetězec nebo kolizní dvojice, která sdílí vnější
    cíl). Dvojice uvnitř jednotky se násobí násobností jednotky, dvojice mezi dvěma jednotkami
    součinem násobností; kopie téže jednotky se navzájem nespojují (každá kopie je nezávislá).
    Správnější než kopie jednotlivých řetězců, kde se kopie téhož nálezu spojily do skupiny."""
    unit = {}
    for c in truth:
        unit[c["chain"]] = ("x", c["ext"]) if c["shared"] else ("c", c["chain"])
    units = sorted(set(unit.values()))
    members = {u: [c for c in unit if unit[c] == u] for u in units}

    def f1(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        return 2 * p * r / (p + r) if p + r else 0.0

    def counts(stat, mult):
        n, N, S, W = stat
        tp = fn = fp = 0.0
        for u, m in mult.items():
            for c in members[u]:
                tp += m * S.get(c, 0)
                fn += m * (N.get(c, 0) - S.get(c, 0))
        for (c, d), w in W.items():
            if c not in unit or d not in unit:
                continue
            uc, ud = unit[c], unit[d]
            if uc == ud:
                fp += mult.get(uc, 0) * w
            else:
                fp += mult.get(uc, 0) * mult.get(ud, 0) * w
        return tp, fp, fn
    rng = random.Random(seed)
    sims = {k: [] for k in arms_stats}
    diffs = {k: [] for k in arms_stats}
    for _ in range(n_boot):
        mult = defaultdict(int)
        for _ in units:
            mult[rng.choice(units)] += 1
        vals = {k: f1(*counts(st, mult)) for k, st in arms_stats.items()}
        for k in arms_stats:
            sims[k].append(vals[k])
            diffs[k].append(vals[k] - vals["B1_ip"])

    def ci(v):
        v = sorted(v)
        return [round(v[int(0.025 * len(v))], 3), round(v[int(0.975 * len(v)) - 1], 3)]
    return {"units": len(units),
            "arms": {k: {"f1_ci": ci(sims[k]), "diff_vs_B1_ci": ci(diffs[k])} for k in arms_stats}}


def cmd_eval(a):
    res = json.load(open(a.result, encoding="utf-8"))
    truth = json.load(open(a.truth, encoding="utf-8"))
    shown = res["shown"]
    label_of = {f["id"]: chain_of(f["text"], truth) for f in shown}
    mapped = [f for f in shown if len(label_of[f["id"]]) == 1]
    out = {"shown": len(shown), "mapped_to_chain": len(mapped),
           "chains_with_findings": len({next(iter(label_of[f["id"]])) for f in mapped}),
           "chains": len(truth), "incidents_report": len(res["incidents"]),
           "stats": res.get("stats", {}), "arms": {}}
    ids = [f["id"] for f in shown]
    arms = {"B0_each": [[i] for i in ids],
            "B1_ip": groups_ip(shown)}
    rng = random.Random(a.seed)
    sizes = [len(g) for g in arms["B1_ip"]]
    shuffled = ids[:]
    rng.shuffle(shuffled)
    b2, pos = [], 0
    for s in sizes:
        b2.append(shuffled[pos:pos + s])
        pos += s
    arms["B2_random"] = b2
    arms["INC_report"] = [i["findings"] for i in res["incidents"]]
    stats = {}
    for name, groups in arms.items():
        out["arms"][name] = metrics(groups, truth, label_of)
        stats[name] = pair_stats(groups, label_of)
    out["bootstrap_chain_copies"] = bootstrap(truth, stats)
    out["bootstrap"] = cluster_bootstrap(truth, stats)
    # ztráta zachycení: řetězec je zachycen, když ho zobrazená položka (nález) obsahuje; incident ho
    # nesmí skrýt (nález zůstává zobrazený), proto je ztráta 0 z konstrukce zobrazení; měří se
    # jen pokrytí řetězců nálezy
    covered = {next(iter(label_of[f["id"]])) for f in mapped}
    out["chain_coverage"] = {"covered": len(covered), "n": len(truth)}
    by_variant = defaultdict(lambda: [0, 0])
    for c in truth:
        by_variant[c["variant"]][1] += 1
        if c["chain"] in covered:
            by_variant[c["variant"]][0] += 1
    out["coverage_by_variant"] = {k: v for k, v in by_variant.items()}
    print(json.dumps(out, indent=1, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--conn", required=True)
    r.add_argument("--bin", required=True)
    r.add_argument("--work", required=True)
    r.add_argument("--scope", default="192.168.1.0/24")
    r.add_argument("--window", type=int, default=1800)
    r.add_argument("--v3-on", default="")
    r.add_argument("--env", action="append", default=[])
    e = sub.add_parser("eval")
    e.add_argument("--result", required=True)
    e.add_argument("--truth", required=True)
    e.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    {"run": cmd_run, "eval": cmd_eval}[a.cmd](a)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
