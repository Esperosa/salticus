"""NTP server s posunutým časem (porucha S11): odpovídá jako stratum 3 s offsetem argv[1] s."""
import socket, struct, sys, time
off = float(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 123))
def ts(t):
    t += 2208988800
    return struct.pack("!II", int(t), int((t % 1) * 2**32))
while True:
    data, addr = s.recvfrom(256)
    if len(data) < 48:
        continue
    now = time.time() + off
    resp = bytes([0x24, 3, data[2], 0xEC]) + struct.pack("!II", 0, 0) + b"LOCL" + ts(now - 1) + data[40:48] + ts(now) + ts(now)
    s.sendto(resp, addr)
