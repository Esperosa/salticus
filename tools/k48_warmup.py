#!/usr/bin/env python3
"""Krok 48: diagnostika studeného startu z kroku 47. Vezme skutečně zachycené pozadí
(toky, které se nedotýkají útočníka) a zopakuje ho s posunutými časovými razítky přes
~50 h před skutečným útokem, aby hostitelé měli zralý profil (PROFILE_MATURE_S = 48 h,
src/protection.rs). Skutečný útok se připojí beze změny, se svým skutečným časem.

  k48_warmup.py --conn zeek/conn.log --out zeek_warm/conn.log [--warmup-hours 50]
"""
import argparse
import os


def read(path):
    header = []
    fields = None
    rows = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#fields"):
                fields = line.rstrip("\n").split("\t")[1:]
                header.append(line)
            elif line.startswith("#"):
                header.append(line)
            else:
                rows.append(line.rstrip("\n").split("\t"))
    return header, fields, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conn", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--attacker", action="append", default=["10.60.1.3", "10.60.5.4"])
    ap.add_argument("--warmup-hours", type=float, default=50.0)
    a = ap.parse_args()
    attacker = set(a.attacker)

    header, fields, rows = read(a.conn)
    ts_i = fields.index("ts")
    oh_i = fields.index("id.orig_h")
    rh_i = fields.index("id.resp_h")
    uid_i = fields.index("uid")
    rows_sorted = sorted(rows, key=lambda r: float(r[ts_i]))
    first_ts = float(rows_sorted[0][ts_i])
    bg = [r for r in rows_sorted if r[oh_i] not in attacker and r[rh_i] not in attacker]
    bg_t0 = float(bg[0][ts_i])
    bg_span = float(bg[-1][ts_i]) - bg_t0
    warmup_s = a.warmup_hours * 3600
    warm_start = first_ts - warmup_s

    out_rows = []
    n_tiles = int(warmup_s // bg_span) + 1
    uid_ctr = 0
    for tile in range(n_tiles):
        tile_t0 = warm_start + tile * bg_span
        if tile_t0 >= first_ts:
            break
        for r in bg:
            new_ts = tile_t0 + (float(r[ts_i]) - bg_t0)
            if new_ts >= first_ts or new_ts < 0:
                continue
            r2 = list(r)
            r2[ts_i] = f"{new_ts:.6f}"
            uid_ctr += 1
            r2[uid_i] = f"Cwarm{uid_ctr:08d}"
            out_rows.append(r2)
    n_synthetic = len(out_rows)
    out_rows.extend(rows_sorted)  # skutečný, nezměněný záznam (pozadí i útok)
    out_rows.sort(key=lambda r: float(r[ts_i]))

    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    with open(a.out, "w", encoding="utf-8", newline="\n") as out:
        for line in header:
            out.write(line)
        for r in out_rows:
            out.write("\t".join(r) + "\n")
    print(f"synteticky zahrivaci tok (jen posunuta razitka realneho pozadi): {n_synthetic}, "
          f"realnych toku: {len(rows_sorted)}, celkem: {len(out_rows)}, "
          f"zahrivani {a.warmup_hours} h pred prvnim tokem utoku")


if __name__ == "__main__":
    main()
