#!/usr/bin/env python3
"""Krok 22: parove srovnani ramen ve svete v2 (F2, F2c, FG2) a svet v1 proti v2 (`impl-krok22.md`).

Stejne metriky jako `tools/k20_gate.py` (K22-1 az K22-4 = K20-1 az K20-4), jine dvojice ramen.
Pouziti: python -I tools/k22_gate.py KOREN [--boot 2000]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import k20_gate  # noqa: E402

k20_gate.PAIRS = [("F2", "FG2"), ("F2", "F2c"), ("F1", "F2"), ("R1", "R2"), ("FG1", "FG2")]

if __name__ == "__main__":
    k20_gate.main()
