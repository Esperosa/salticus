#!/usr/bin/env python3
"""Krok 21: parove srovnani ramen F, FG20, FG21 a FG21P (`docs/diplomka/eval/impl-krok21.md`).

Stejne metriky a kriteria jako `tools/k20_gate.py` (K20-1 az K20-4 = K21-1 az K21-4), jen jine
dvojice ramen. Pouziti: python tools/k21_gate.py KOREN [--boot 2000]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k20_gate  # noqa: E402

k20_gate.PAIRS = [("F", "FG21"), ("F", "FG21P"), ("FG20", "FG21"), ("FG21", "FG21P")]

if __name__ == "__main__":
    k20_gate.main()
