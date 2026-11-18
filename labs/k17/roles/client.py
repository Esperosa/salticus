"""Běžný provoz klienta: HTTP, HTTPS, DNS, občas stažení souboru; chyby do syslogu."""
import random, socket, ssl, syslog, time, urllib.request
syslog.openlog("webclient", 0, syslog.LOG_USER)
ctx = ssl.create_default_context(cafile="/out/ca/ca.pem")
rnd = random.Random(socket.gethostname())
URLS = ["http://web.lab.test/", "https://web.lab.test/", "http://app.lab.test/", "https://api.lab.test/",
        "http://files.lab.test/file"]
W = [5, 5, 4, 3, 1]
while True:
    url = rnd.choices(URLS, W)[0]
    try:
        with urllib.request.urlopen(url, timeout=8, context=ctx if url.startswith("https") else None) as r:
            r.read()
    except Exception as e:  # noqa: BLE001 - klient loguje jakoukoli chybu
        syslog.syslog(syslog.LOG_WARNING, f"request {url} failed: {e}")
    if rnd.random() < 0.3:
        try:
            socket.getaddrinfo(rnd.choice(["web.lab.test", "app.lab.test", "ntp.lab.test", "ns.lab.test"]), 80)
        except OSError as e:
            syslog.syslog(syslog.LOG_WARNING, f"resolve failed: {e}")
    time.sleep(rnd.uniform(1.5, 5.0))
