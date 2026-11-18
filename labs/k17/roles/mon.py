"""Monitorovací host: kontroly s Nagios sémantikou (stav při změně, HARD po 3 pokusech).

Výstup /out/logs/nagios.log ve formátu Nagios logu: `[epoch] SERVICE ALERT: host;svc;STATE;TYPE;n;output`
a `[epoch] HOST ALERT: host;DOWN;HARD;n;output`. Texty výstupu odpovídají pluginům check_http,
check_ssl_cert, check_dns, check_ntp_time a check_ping.
"""
import socket, ssl, struct, subprocess, time, urllib.request

LOG = "/out/logs/nagios.log"
CA = "/out/ca/ca.pem"
state = {}

def emit(line):
    with open(LOG, "a") as f:
        f.write(f"[{int(time.time())}] {line}\n")

def record(kind, host, svc, ok, crit_text, ok_text):
    key = (kind, host, svc)
    st = state.setdefault(key, {"hard": "OK", "n": 0})
    if ok:
        if st["hard"] != "OK":
            if kind == "HOST":
                emit(f"HOST ALERT: {host};UP;HARD;1;{ok_text}")
            else:
                emit(f"SERVICE ALERT: {host};{svc};OK;HARD;1;{ok_text}")
        st.update(hard="OK", n=0)
        return
    st["n"] += 1
    typ = "HARD" if st["n"] >= 3 else "SOFT"
    if st["hard"] == "OK" or typ == "SOFT":
        if kind == "HOST":
            emit(f"HOST ALERT: {host};DOWN;{typ};{min(st['n'], 3)};{crit_text}")
        else:
            emit(f"SERVICE ALERT: {host};{svc};CRITICAL;{typ};{min(st['n'], 3)};{crit_text}")
    if typ == "HARD":
        st["hard"] = "CRITICAL"

def ping(ip):
    r = subprocess.run(["ping", "-c", "3", "-W", "1", "-q", ip], capture_output=True, text=True)
    loss = 100
    for part in r.stdout.split(","):
        if "packet loss" in part:
            loss = int(float(part.strip().split("%")[0]))
    return loss

def http(host, ip, path="/", tls=False):
    url = f"{'https' if tls else 'http'}://{host}{path}"
    t = time.time()
    try:
        req = urllib.request.Request(url)
        ctx = ssl.create_default_context(cafile=CA) if tls else None
        with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
            r.read()
            return True, f"HTTP OK: HTTP/1.1 {r.status} - {time.time() - t:.3f} second response time"
    except urllib.error.HTTPError as e:
        return False, f"HTTP CRITICAL: HTTP/1.1 {e.code} - {time.time() - t:.3f} second response time"
    except Exception as e:  # noqa: BLE001
        return False, f"CRITICAL - Socket timeout or connection failure: {e}"

def cert(ip):
    ctx = ssl.create_default_context(cafile=CA)
    try:
        with socket.create_connection((ip, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname="web.lab.test"):
                return True, "SSL OK - Certificate 'web.lab.test' valid"
    except ssl.SSLCertVerificationError as e:
        if "expired" in str(e):
            return False, "SSL CRITICAL - Certificate 'web.lab.test' expired"
        return False, f"SSL CRITICAL - {e.verify_message}"
    except Exception as e:  # noqa: BLE001
        return False, f"SSL CRITICAL - connection failed: {e}"

def dig(server, name):
    t = time.time()
    r = subprocess.run(["dig", f"@{server}", name, "A", "+time=3", "+tries=1", "+noall", "+answer", "+comments"],
                       capture_output=True, text=True)
    dt = time.time() - t
    status = "TIMEOUT"
    for line in r.stdout.splitlines():
        if "status:" in line:
            status = line.split("status:")[1].split(",")[0].strip()
    addrs = [l.split()[-1] for l in r.stdout.splitlines() if l and not l.startswith(";") and "\tA\t" in l.replace(" ", "\t")]
    return status, addrs, dt

def dns_check():
    status, got, dt = dig("10.77.2.53", "app.lab.test")
    _, want, _ = dig("10.77.2.54", "app.lab.test")
    if status == "TIMEOUT":
        return False, "DNS CRITICAL - query timed out"
    if status != "NOERROR":
        return False, f"DNS CRITICAL - query returned {status}"
    if want and got and sorted(got) != sorted(want):
        return False, f"DNS CRITICAL - expected '{','.join(want)}' but got '{','.join(got)}'"
    if dt > 1.0:
        return False, f"DNS CRITICAL - {dt:.3f} seconds response time"
    return True, f"DNS OK: {dt:.3f} seconds response time"

def ntp_check(ip):
    pkt = b"\x1b" + 47 * b"\0"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
        t0 = time.time(); s.sendto(pkt, (ip, 123)); data, _ = s.recvfrom(256); t3 = time.time()
        secs, frac = struct.unpack("!II", data[40:48])
        server = secs - 2208988800 + frac / 2**32
        off = server - (t0 + t3) / 2
        if abs(off) > 1.0:
            return False, f"NTP CRITICAL: Offset {off:.3f} secs"
        return True, f"NTP OK: Offset {off:.6f} secs"
    except Exception:  # noqa: BLE001
        return False, "NTP CRITICAL: No response from NTP server"

open(LOG, "a").close()
while True:
    for ip in ("10.77.1.254", "10.77.2.10", "10.77.2.53", "10.77.2.123"):
        loss = ping(ip)
        record("HOST", ip, "", loss < 100, f"PING CRITICAL - Packet loss = {loss}%", f"PING OK - Packet loss = {loss}%")
    ok, txt = http("web.lab.test", "10.77.2.10"); record("SERVICE", "10.77.2.10", "HTTP", ok, txt, txt)
    ok, txt = http("app.lab.test", "10.77.2.10"); record("SERVICE", "10.77.2.10", "HTTP app", ok, txt, txt)
    ok, txt = http("files.lab.test", "10.77.2.10", "/file"); record("SERVICE", "10.77.2.10", "HTTP files", ok, txt, txt)
    ok, txt = cert("10.77.2.10"); record("SERVICE", "10.77.2.10", "SSL cert", ok, txt, txt)
    ok, txt = dns_check(); record("SERVICE", "10.77.2.53", "DNS", ok, txt, txt)
    ok, txt = ntp_check("10.77.2.123"); record("SERVICE", "10.77.2.123", "NTP time", ok, txt, txt)
    time.sleep(10)
