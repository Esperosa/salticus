#!/usr/bin/env python3
"""LUFlow (denni zip z F:\Projekty\bakula-datasets\luflow) -> Zeek `conn.log.labeled`.

Stitky se NEMICHAJI do ciziho schematu: `benign` -> Benign, `malicious` -> Malicious,
`outlier` (neoznaceno zdrojem) -> Unknown. Anonymizovane ciselne adresy zdroje se
mapuji deterministicky na 10.x.y.1 (bez navratove tabulky, jen pro replay), skutecne
IP zustavaji. Vystup je radky podle casu. Parametry: ZIP CSV_NAME OUT [--max N].
Pouziti: python -I luflow_to_zeek.py <zip> <out.conn.log.labeled> [max_rows]
"""
import csv
import io
import sys
import zipfile

PROTO = {"6": "tcp", "17": "udp", "1": "icmp"}
LABEL = {"benign": "Benign", "malicious": "Malicious", "outlier": "Unknown"}


def mapip(value):
    if value.isdigit():
        n = int(value)
        return f"10.{(n // 250) % 250}.{n % 250}.1"
    return value


def main():
    zip_path, out_path = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    archive = zipfile.ZipFile(zip_path)
    name = archive.namelist()[0]
    rows = []
    with archive.open(name) as raw:
        reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8"))
        for r in reader:
            try:
                ts = int(r["time_start"]) / 1e6
            except ValueError:
                continue
            rows.append((ts, r))
            if limit and len(rows) >= limit:
                break
    rows.sort(key=lambda x: x[0])
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
              "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
              "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
              "tunnel_parents", "label", "detailed-label"]
    with open(out_path, "w", encoding="utf-8", newline="\n") as out:
        out.write("#separator \x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        out.write("#fields\t" + "\t".join(fields) + "\n")
        for i, (ts, r) in enumerate(rows):
            bin_, bout = int(float(r["bytes_in"] or 0)), int(float(r["bytes_out"] or 0))
            # LUFlow: bytes_out = od klienta? zdroj popisuje smer vuci "src"; drzime shodne s Joy:
            # bytes_out = odeslano zdrojem, bytes_in = prijato zdrojem
            state = "SF" if bin_ > 0 else "S0"
            label = LABEL.get(r["label"], "Unknown")
            vals = [f"{ts:.6f}", f"L{i}", mapip(r["src_ip"]), r["src_port"], mapip(r["dest_ip"]),
                    r["dest_port"], PROTO.get(r["proto"], "other"), "-", r["duration"], str(bout),
                    str(bin_), state, "-", "-", "0", "-", r["num_pkts_out"], "-", r["num_pkts_in"], "-",
                    "-", label, "-" if label != "Malicious" else "malicious"]
            out.write("\t".join(vals) + "\n")
    print(f"{len(rows)} toku -> {out_path}")


if __name__ == "__main__":
    main()
