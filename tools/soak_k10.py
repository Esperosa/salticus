#!/usr/bin/env python3
"""Krok 10 (impl-krok10.md, A): smycka chyba -> poucení.

Z behu soaku (`networks.jsonl`) a tabulky rodin (`salticus-program soak families`)
vyrobi ABSTRAKTNI zaznamy chyb: zmeskany utok, omylem zavreny nalez, spatny typ.
Zaznam nese jen tridy rysu chovani (taktika, tempo, objem, topologie, protokol,
trida portu, pocet zdroju, viditelnost IDS), nikdy seed, id site ani adresu.
Vystupy:
  lessons.jsonl  abstraktni zaznamy (jeden radek = jedna chyba)
  causes.md      shluky podle rysu a spolecne priciny (podil chyb, "lift" proti zakladu)
  corpus.jsonl   parametricke regresni scenare (nejcastejsi shluky chyb)
Jen standardni knihovna Pythonu 3.
"""
import argparse
import csv
import json
import math
import os
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from soak_coverage import attacks, load, wilson  # noqa: E402

FEATURES = ["tactic", "proto", "tempo", "volume", "topology", "sources", "port_class", "ids"]


def read_table(path):
    table = {}
    with open(path, encoding="utf-8") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            table[row["label"]] = row
    return table


def features(info, record):
    return {
        "tactic": info.get("tactic") or "none",
        "proto": info.get("proto") or "tcp",
        "tempo": info.get("tempo") or "instant",
        "volume": info.get("volume") or "tiny",
        "topology": info.get("topology") or "one_to_one",
        "sources": info.get("sources") or "1",
        "port_class": info.get("port_class") or "other",
        "ids": "ids" if record.get("ids_visible") else "no_ids",
    }


def lessons_from(rows, table):
    all_items, lessons = [], []
    for _, a in attacks(rows):
        info = table.get(a["family"])
        if info is None:
            continue
        feat = features(info, a)
        cat = info.get("category", "security")
        expected = {"security": "security", "ops_fault": "ops_fault", "benign_change": "benign_change"}.get(cat, "unknown")
        all_items.append(feat)
        k7 = a.get("k7") or {}
        if not a["cf"]:
            lessons.append(dict(kind="missed_attack", expected_class=expected, observed_class="unknown",
                                finding_type=None, failed_check="none", **feat))
        else:
            types = set(filter(None, info.get("expected_types", "").split(",")))
            if types and not (types & set(a.get("cf_types", []))):
                lessons.append(dict(kind="misclassified", expected_class=expected, observed_class=expected,
                                    finding_type=(a.get("cf_types") or [None])[0], failed_check="none", **feat))
            if k7.get("wrong_closed", 0) > 0:
                lessons.append(dict(kind="wrong_closed", expected_class=expected, observed_class="unknown",
                                    finding_type=(a.get("cf_types") or [None])[0], failed_check="none", **feat))
    return all_items, lessons


def pc(x):
    return f"{100 * x:.1f}".replace(".", ",")


def causes(all_items, lessons, min_n=30):
    """Pro kazdou hodnotu rysu: podil chyb a lift proti celkovemu podilu."""
    base = len(lessons) / max(len(all_items), 1)
    total = Counter()
    miss = Counter()
    for feat in all_items:
        for k in FEATURES:
            total[(k, feat[k])] += 1
    for les in lessons:
        for k in FEATURES:
            miss[(k, les[k])] += 1
    out = []
    for key, n in total.items():
        if n < min_n:
            continue
        m = miss.get(key, 0)
        p, lo, hi = wilson(m, n)
        out.append((key, n, m, p, lo, hi, p / base if base else float("nan")))
    out.sort(key=lambda r: -r[3])
    return base, out


def clusters(all_items, lessons, min_n=10):
    total = Counter()
    bad = Counter()
    key_of = lambda f: tuple(f[k] for k in ("tactic", "tempo", "volume", "topology", "sources", "port_class", "ids"))
    for f in all_items:
        total[key_of(f)] += 1
    for l in lessons:
        bad[key_of(l)] += 1
    rows = [(k, total[k], bad[k]) for k in total if total[k] >= min_n and bad[k] > 0]
    rows.sort(key=lambda r: (-r[2] / r[1], -r[2]))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", nargs="+", required=True, help="adresare behu")
    ap.add_argument("--families", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()
    table = read_table(args.families)
    rows = load(args.arm)
    all_items, lessons = lessons_from(rows, table)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "lessons.jsonl"), "w", encoding="utf-8") as handle:
        for les in lessons:
            handle.write(json.dumps(les, ensure_ascii=False, sort_keys=True) + "\n")
    base, causal = causes(all_items, lessons)
    cl = clusters(all_items, lessons)
    lines = [f"# Společné příčiny chyb ({len(all_items)} útoků a poruch, {len(lessons)} záznamů chyb)", "",
             f"Základní podíl chyb: {pc(base)} %. Lift = podíl chyb u hodnoty rysu / základní podíl.", "",
             "| rys | hodnota | n | chyb | podíl % (Wilson) | lift |", "|---|---|---:|---:|---|---:|"]
    for (k, v), n, m, p, lo, hi, lift in causal[: args.top]:
        lines.append(f"| {k} | {v} | {n} | {m} | {pc(p)} ({pc(lo)} až {pc(hi)}) | {lift:.2f} |".replace(".", ",", 0))
    lines += ["", "## Shluky podle kombinace rysů (n ≥ 10)", "",
              "| taktika | tempo | objem | topologie | zdroje | třída portu | IDS | n | chyb | podíl % |",
              "|---|---|---|---|---|---|---|---:|---:|---|"]
    for k, n, bad in cl[: args.top]:
        lines.append("| " + " | ".join(k) + f" | {n} | {bad} | {pc(bad / n)} |")
    with open(os.path.join(args.out, "causes.md"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    # korpus: nejcastejsi shluky chyb jako parametricke scenare (jen abstraktni rysy)
    with open(os.path.join(args.out, "corpus.jsonl"), "w", encoding="utf-8") as handle:
        for k, n, bad in cl[: args.top]:
            tactic, tempo, volume, topology, sources, port_class, ids = k
            handle.write(json.dumps(dict(
                tactic=tactic, tempo=tempo, volume=volume, topology=topology, sources=sources,
                port_class=port_class, ids=ids, support=n, miss_rate=round(bad / n, 4)),
                ensure_ascii=False, sort_keys=True) + "\n")
    print(f"zaznamu chyb {len(lessons)}, shluku {len(cl)}, vystup {args.out}")


if __name__ == "__main__":
    main()
