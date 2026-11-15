#!/usr/bin/env python3
"""Krok 13: rozdeleni L7 veličin z logu Zeeku (dns.log, ssl.log, x509.log, conn.log).
Pouziti: python -I tools/k13_real_stats.py NAZEV=DIR [NAZEV=DIR ...]"""
import collections, math, sys, os


def rows(path):
    fields = None
    if not os.path.exists(path):
        return
    for l in open(path, encoding="utf-8", errors="replace"):
        if l.startswith("#fields"):
            fields = l.rstrip("\n").split("\t")[1:]
        elif not l.startswith("#") and fields:
            yield dict(zip(fields, l.rstrip("\n").split("\t")))


def ent(s):
    c = collections.Counter(s)
    n = len(s)
    return -sum(k / n * math.log2(k / n) for k in c.values()) if n else 0.0


def stats(d):
    out = {}
    dns = list(rows(d + "/dns.log"))
    out["dns_rows"] = len(dns)
    if dns:
        ans = [r for r in dns if r.get("rcode_name") not in ("-", None)]
        out["nxdomain"] = sum(r["rcode_name"] == "NXDOMAIN" for r in ans) / max(len(ans), 1)
        out["txt_null"] = sum(r.get("qtype_name") in ("TXT", "NULL") for r in dns) / len(dns)
        out["aaaa"] = sum(r.get("qtype_name") == "AAAA" for r in dns) / len(dns)
        names = {r["query"].lower().rstrip(".") for r in dns if r.get("query") not in ("-", None)}
        out["names"] = len(names)
        lab = [n.split(".")[0] for n in names]
        out["longhi_names"] = sum(len(l) >= 24 and ent(l) >= 3.0 for l in lab) / max(len(lab), 1)
        out["label_p50"] = sorted(map(len, lab))[len(lab) // 2] if lab else 0
    ssl = list(rows(d + "/ssl.log"))
    out["ssl_rows"] = len(ssl)
    if ssl:
        out["no_sni"] = sum(r.get("server_name") in ("-", None) for r in ssl) / len(ssl)
        out["ssl_established"] = sum(r.get("established") == "T" for r in ssl) / len(ssl)
    x = list(rows(d + "/x509.log"))
    n = young = selfs = 0
    for r in x:
        try:
            nb, ts = float(r["certificate.not_valid_before"]), float(r["ts"])
        except (KeyError, ValueError):
            continue
        n += 1
        young += (ts - nb) < 30 * 86400
        selfs += r.get("certificate.subject") == r.get("certificate.issuer")
    out["x509"] = n
    if n:
        out["self_signed"] = selfs / n
        out["young_lt30d"] = young / n
    return out


if __name__ == "__main__":
    for a in sys.argv[1:]:
        name, d = a.split("=", 1)
        s = stats(d)
        print(name, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in s.items()})
