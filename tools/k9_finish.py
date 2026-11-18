#!/usr/bin/env python3
"""Vygeneruje vsechny tabulky kroku 9 a 10 z hotovych behu v F:/Projekty/bakula-soak/k9.

Behy chybejici na disku se preskoci a vypise se, co chybi. Pouziti (z korene repa):
  python tools/k9_finish.py [--soak F:/Projekty/bakula-soak/k9] [--bin F:/work-tmp/k9bin/k9-b9.exe]
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def dirs(soak, arm, seeds):
    found = [os.path.join(soak, f"{arm}-{s}") for s in seeds]
    ok = [d for d in found if os.path.exists(os.path.join(d, "final-report.md"))]
    return ok, [d for d in found if d not in ok]


def run(cmd):
    print(" ".join(cmd))
    subprocess.run([sys.executable, "-X", "utf8"] + cmd, check=False, cwd=ROOT)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--soak", default="F:/Projekty/bakula-soak/k9")
    ap.add_argument("--bin", default="F:/work-tmp/k9bin/k9-b9.exe")
    args = ap.parse_args()
    soak = args.soak
    families = os.path.join(soak, "families.tsv")
    with open(families, "w", encoding="utf-8", newline="") as handle:
        handle.write(subprocess.run([args.bin, "soak", "families"], capture_output=True, text=True, encoding="utf-8").stdout)
    tuning = ["20261102", "20261103", "20261104", "20262201", "20262202", "20262301", "20262302"]
    held = ["20261901", "20262001", "20262101", "20262102", "20261201", "20261301"]
    os.makedirs(os.path.join(ROOT, "docs/diplomka/eval/k9"), exist_ok=True)
    os.makedirs(os.path.join(ROOT, "docs/diplomka/eval/k10"), exist_ok=True)

    def compare(base_arms, cand_arms, seeds, out, title):
        b, c = [], []
        for arm in base_arms:
            ok, _ = dirs(soak, arm, seeds)
            b += ok
        for arm in cand_arms:
            ok, _ = dirs(soak, arm, seeds)
            c += ok
        if not b or not c:
            print("preskoceno (chybi behy):", out)
            return
        run(["tools/k9_final.py", "--families", families, "--base", "base", ",".join(b),
             "--cand", "cand", ",".join(c), "--out", os.path.join(ROOT, out), "--title", title])

    compare(["k8ref"], ["c8", "c9"], tuning, "docs/diplomka/eval/k9/vysledky.md", "Výsledky kroku 9, ladicí seedy")
    off = [d for a, sd in (("b6noep", ["20261102"]), ("c9off", ["20261103", "20261104"])) for d in dirs(soak, a, sd)[0]]
    on = [d for a, sd in (("b4", ["20261102"]), ("c8", ["20261103", "20261104"])) for d in dirs(soak, a, sd)[0]]
    if off and on:
        run(["tools/k9_final.py", "--families", families, "--base", "off", ",".join(off), "--cand", "on", ",".join(on),
             "--out", os.path.join(ROOT, "docs/diplomka/eval/k9/endpoint.md"), "--title", "Koncová telemetrie: vypnuto (základ) proti zapnuto (kandidát)"])
    compare(["heldref"], ["heldc"], held, "docs/diplomka/eval/k9/held.md", "Výsledky kroku 9, držené seedy (jednou)")
    compare(["k10ref"], ["k10c"], ["20262401", "20262402"], "docs/diplomka/eval/k10/vysledky.md", "Krok 10: tvrdé záporné scénáře a nové seedy (svět k10)")
    compare(["noise10ref"], ["noise10"], ["20262301"], "docs/diplomka/eval/k10/sum10x.md", "Krok 10: šum 10x (kombinace útok + porucha + šum + výpadek senzoru)")
    cand = []
    for arm in ("c8", "c9"):
        cand += dirs(soak, arm, tuning)[0]
    if cand:
        run(["tools/k9_coverage_table.py", "--families", families, "--arm"] + cand + ["--out", os.path.join(ROOT, "docs/diplomka/eval/k9/pokryti.md")])
        run(["tools/soak_k10.py", "--arm"] + cand + ["--families", families, "--out", os.path.join(ROOT, "docs/diplomka/eval/k10")])
    run(["tools/readme_status.py"])


if __name__ == "__main__":
    main()
