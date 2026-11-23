#!/usr/bin/env python3
"""IoT-23 `datasetN.csv` (Zenodo) -> Zeek `conn.log.labeled` (TSV) pro `k30_ctu13.py --zeek`."""
import sys

HEADER = ("ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes "
          "conn_state local_orig local_resp missed_bytes history orig_pkts orig_ip_bytes resp_pkts "
          "resp_ip_bytes tunnel_parents label detailed-label").split()


def convert(src, dst):
    n = 0
    with open(src, encoding="utf-8", errors="replace") as fh, open(dst, "w", encoding="utf-8", newline="\n") as out:
        out.write("#separator \x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n")
        out.write("#fields\t" + "\t".join(HEADER) + "\n")
        next(fh)
        for line in fh:
            line = line.rstrip("\n")
            head = line.split(",", 20)
            if len(head) < 21:
                continue
            tail = head[20].split()  # tunnel_parents, label, detailed-label oddělené mezerami
            if len(tail) < 2:
                continue
            tp, label = tail[0], tail[1]
            detailed = tail[2] if len(tail) > 2 else "-"
            out.write("\t".join(head[:20] + [tp, label, detailed]) + "\n")
            n += 1
    return n


if __name__ == "__main__":
    print(convert(sys.argv[1], sys.argv[2]))
