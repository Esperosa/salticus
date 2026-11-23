#!/usr/bin/env python3
"""Krok 27: benchmark vložených útoků přehraný po oknech celou produkční cestou v3.

Na rozdíl od `k25_inject.py eval` (jeden běh nad celým záznamem) tu stav (profil, novost,
paměť nálezů, historie objemu, hystereze beaconingu) přežívá mezi okny, takže se měří i
stavové vrstvy. Vyhodnocují se jen nálezy, které produkt skutečně zobrazí
(`findingLifecycle[].displayed`), ne všechny události.

Použití:
  k27_cycles.py --conn bench/zeek/conn.log --truth bench/truth.json --bin salticus-program.exe \
      --work DIR [--window 1800] [--v3-on attempts] [--env SALTICUS_KNOWN_ACTIVITY=cesta.json]
"""
import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


replay = load("replay_public")
inject = load("k25_inject")

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--truth", required=True)
    ap.add_argument("--bin", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--scope", default="192.168.1.0/24")
    ap.add_argument("--window", type=int, default=1800)
    ap.add_argument("--v3-on", default="")
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument("--out")
    a = ap.parse_args()

    fields, rows = replay.read_conn(a.conn)
    truth = json.load(open(a.truth, encoding="utf-8"))
    t0 = rows[0]["_ts"]
    windows = defaultdict(list)
    for r in rows:
        windows[int((r["_ts"] - t0) // a.window)].append(r)
    order = sorted(windows)

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

    shown_text = {}      # finding_id -> text (jen zobrazené)
    shown_per_window = []
    failures = 0
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
            sys.stderr.write(proc.stderr[-1500:])
            continue
        report = replay.latest_report(workspace)
        findings = {f["finding_id"]: f for f in report.get("findings", [])}
        shown = 0
        for record in report.get("findingLifecycle", []):
            if not record.get("displayed"):
                continue
            f = findings.get(record["finding_id"], {})
            # celý nález (finding_id u nespárovaných událostí nese zdrojovou IP)
            text = json.dumps(f, ensure_ascii=False)
            if f.get("finding_type") not in ("unexpected_traffic",):
                # stejné id se zobrazuje opakovaně s novými důkazy (nespárované události jsou
                # podle cíle), proto se ukládá každý odlišný text zvlášť
                shown_text.setdefault((record["finding_id"], hash(text)), (start, text))
            shown += 1
        shown_per_window.append(shown)
        # pracovní okno se nemaže, run adresáře se průběžně promazávají kvůli místu
        runs = os.path.join(workspace, "runs")
        names = sorted(os.listdir(runs))
        for old in names[:-3]:
            if old.startswith("run-"):
                import shutil
                shutil.rmtree(os.path.join(runs, old), ignore_errors=True)

    # IP -> časy začátků oken, ve kterých byl poprvé zobrazen nález, který ji zmiňuje
    ip_times = defaultdict(list)
    for first, text in shown_text.values():
        for ip in set(IP_RE.findall(text)):
            ip_times[ip].append(first)

    by = defaultdict(list)
    for t in truth:
        by[t["family"]].append(t)
    result = {"windows": len(order), "failures": failures,
              "displayed_total": sum(shown_per_window),
              "displayed_distinct": len(shown_text), "families": {}}
    print(f"okna {len(order)}, selhání {failures}, zobrazeno celkem {sum(shown_per_window)}, "
          f"odlišných zobrazených nálezů (bez neočekávaného provozu) {len(shown_text)}")
    print(f"{'rodina':22} {'druh':8} {'zobrazeno':>10}  95% interval")
    for fam in inject.FAMILIES:
        eps = by.get(fam, [])
        key = "dst" if fam == "scanner_spoof" else "src"
        # detekce se počítá jen z nálezů zobrazených od začátku útoku (okno před ním nepatří)
        hit = sum(1 for t in eps
                  if any(ft >= (t.get("t") or 0) - a.window for ft in ip_times.get(t[key], [])))
        lo, hi = inject.wilson(hit, len(eps))
        result["families"][fam] = {"hit": hit, "n": len(eps)}
        print(f"{fam:22} {eps[0]['kind']:8} {hit:>5}/{len(eps):<4} [{lo:.2f},{hi:.2f}]")
    if a.out:
        json.dump(result, open(a.out, "w", encoding="utf-8"), indent=1)
        shown_path = os.path.join(os.path.dirname(a.out), "shown.json")
        json.dump({f"{k[0]}#{k[1]}": [v[0], v[1]] for k, v in shown_text.items()},
                  open(shown_path, "w", encoding="utf-8"))


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
