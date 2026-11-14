#!/usr/bin/env python3
"""Krok 12: hranice automatizace, omylem zavrene a ECE z behu `networks.jsonl`.

Hlasi po ramenech: co program rozhodl sam (zavreni kontextem, vyvraceni zebrikem,
potvrzeni zebrikem), co predal cloveku (eskalovano) a horni mez Wilson 95 % chyby
autonomniho rozhodnuti: omylem zavreny utok (zavreni a vyvraceni, kontrafaktual),
omylem potvrzeny neskodny pripad (potvrzeno bez utoku). ECE posterioru zebriku z
kalibracnich kosu (`calib_raw`). Pouziti:
  python tools/k12_boundary.py --arm NAZEV DIR[,DIR...] [--arm ...] [--out FILE]
"""
import argparse
import json
import math
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_calib import metrics, pool  # noqa: E402
from soak_coverage import wilson  # noqa: E402


def upper(k, n):
    return wilson(k, n)[2] if n else float("nan")


def pc(x, d=2):
    return "-" if x != x else f"{100 * x:.{d}f}".replace(".", ",")


def read(dirs):
    rows = []
    for d in dirs:
        with open(os.path.join(d, "networks.jsonl"), encoding="utf-8") as handle:
            rows += [json.loads(l) for l in handle if l.strip()]
    return rows


def summarize(rows):
    c = Counter()
    for r in rows:
        o = r["output"]
        for k in ("ladder_cases", "ladder_confirmed", "ladder_refuted", "ladder_escalated",
                  "ladder_confirmed_attack", "ladder_escalated_attack", "ladder_refuted_wrong_cf",
                  "auto_closures", "auto_closures_wrong_cf", "ladder_latency_sum", "ladder_decided_attack"):
            c[k] += o.get(k, 0)
        for a in r.get("attacks", []):
            if a.get("emitted"):
                c["attacks"] += 1
                c["attacks_wrong_closed"] += int((a.get("k7") or {}).get("wrong_closed", 0) > 0)
        for k, v in (o.get("ladder_escalated_budget") and {"x": 0}).items() if False else []:
            pass
    return c


def render(name, rows):
    c = summarize(rows)
    decided = c["ladder_confirmed"] + c["ladder_refuted"] + c["ladder_escalated"]
    auto = c["ladder_confirmed"] + c["ladder_refuted"]
    out = [f"### Rameno `{name}` ({len(rows)} sítí, {c['attacks']} útoků s toky)", ""]
    out += ["| ukazatel | hodnota | horní mez Wilson 95 % |", "|---|---|---|"]
    k, n = c["attacks_wrong_closed"], c["attacks"]
    out.append(f"| útoky s omylem zavřeným nálezem (zavření nebo vyvrácení) | {k} z {n} ({pc(k / max(n, 1))} %) | {pc(upper(k, n))} % |")
    k, n = c["ladder_refuted_wrong_cf"], c["ladder_refuted"]
    out.append(f"| vyvrácení žebříkem, z nich omylem (nález chybí bez útoku) | {k} z {n} ({pc(k / max(n, 1))} %) | {pc(upper(k, n))} % |")
    k, n = c["auto_closures_wrong_cf"], c["auto_closures"]
    out.append(f"| zavření kontextem, z nich omylem (kontrafaktuál) | {k} z {n} | {pc(upper(k, n))} % |")
    conf, conf_atk = c["ladder_confirmed"], c["ladder_confirmed_attack"]
    k, n = conf - conf_atk, conf
    out.append(f"| potvrzení žebříkem, z nich neškodné (omylem eskalované jako útok) | {k} z {n} ({pc(k / max(n, 1))} %) | {pc(upper(k, n))} % |")
    out.append(f"| případů žebříku rozhodnutých | {decided} | |")
    out.append(f"| z toho autonomně (potvrzeno + vyvráceno) | {auto} ({pc(auto / max(decided, 1), 1)} %) | |")
    esc = c["ladder_escalated"]
    esc_atk = c["ladder_escalated_attack"]
    out.append(f"| předáno člověku (eskalováno) | {esc} ({pc(esc / max(decided, 1), 1)} %); z nich útok {esc_atk}, neškodné {esc - esc_atk} | |")
    bins = pool([(0, 0, r["output"].get("calib_raw") or []) for r in rows])
    brier, ece, nb = metrics(bins)
    out.append(f"| ECE posterioru žebříku (surová, 10 košů), Brier, n | ECE {pc(ece, 1)} %, Brier {brier:.3f}, n = {nb} | |")
    if c["ladder_cases"]:
        out.append(f"| průměrný čas k rozhodnutí (cykly) | {c['ladder_latency_sum'] / max(decided, 1):.2f} | |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", nargs=2, action="append", metavar=("NAME", "DIRS"), required=True)
    ap.add_argument("--out")
    args = ap.parse_args()
    text = "\n\n".join(render(name, read(dirs.split(","))) for name, dirs in args.arm)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as h:
            h.write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
