# Krok 17: jeden obraz pro všechny role laboratoře (veřejné balíčky Alpine).
FROM alpine:3.24
RUN apk add --no-cache bash iproute2 iptables tcpdump net-snmp net-snmp-tools dnsmasq unbound nsd \
    chrony nmap nmap-scripts curl bind-tools arpwatch supervisor nginx python3 \
    py3-cryptography iperf3 busybox-extras openssl arping coreutils rsyslog py3-pip ruby make gcc g++ musl-dev linux-headers openssl-dev ruby-dev && pip install --break-system-packages --no-cache-dir scapy==2.6.1
CMD ["sleep", "infinity"]
