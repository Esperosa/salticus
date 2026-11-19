"""Krok 22, laboratoř C: služby a úlohy uzlů (jen standardní knihovna Pythonu).

Služby (argumenty kontejneru): http (tcp/80, soubor 1 MB), share (tcp/445 vrací data jako
sdílení souborů), db (tcp/5432 vrací výpis databáze), sink (tcp/443 přijme a zahodí), client
(pravidelný http na web), idle. Úlohy (docker exec): backup CIL..., batch, exfil MB.
"""
import os
import random
import socket
import socketserver
import sys
import threading
import time
import urllib.request

CHUNK = b"x" * 65536


class Sender(socketserver.BaseRequestHandler):
    size = 0

    def handle(self):
        left = self.size
        try:
            self.request.recv(64)
        except OSError:
            pass
        while left > 0:
            n = min(left, len(CHUNK))
            try:
                self.request.sendall(CHUNK[:n])
            except OSError:
                return
            left -= n


class Sink(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            try:
                if not self.request.recv(65536):
                    return
            except OSError:
                return


class Http(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.recv(4096)
            body = CHUNK * 16
            self.request.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        except OSError:
            pass


def serve(port, handler, size=0):
    cls = type("H%d" % port, (handler,), {"size": size})
    srv = socketserver.ThreadingTCPServer(("0.0.0.0", port), cls)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def fetch(host, port, hello=b"GET\n"):
    total = 0
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(hello)
        while True:
            data = s.recv(65536)
            if not data:
                return total
            total += len(data)


def main():
    args = sys.argv[1:]
    if args and args[0] == "backup":
        for target in args[1:]:
            print(target, fetch(target, 445), flush=True)
        return
    if args and args[0] == "batch":
        print(fetch("10.77.2.20", 5432), flush=True)
        return
    if args and args[0] == "exfil":
        left = int(args[1]) * 1024 * 1024
        with socket.create_connection(("10.77.9.9", 443), timeout=10) as s:
            while left > 0:
                s.sendall(CHUNK)
                left -= len(CHUNK)
        return
    if "http" in args:
        serve(80, Http)
    if "share" in args:
        serve(445, Sender, 40 * 1024 * 1024)
    if "db" in args:
        serve(5432, Sender, 60 * 1024 * 1024)
    if "sink" in args:
        serve(443, Sink)
    rnd = random.Random(os.getpid())
    while True:
        if "client" in args:
            try:
                urllib.request.urlopen("http://10.77.2.10/", timeout=5).read()
            except OSError:
                pass
            time.sleep(rnd.uniform(3, 8))
        else:
            time.sleep(60)


if __name__ == "__main__":
    main()
