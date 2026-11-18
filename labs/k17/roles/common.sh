# Společné: odesílání syslogu do sběrného serveru a trasy mezi podsítěmi přes směrovač.
SYSLOG=10.77.2.50
start_syslog() { syslogd -R $SYSLOG:514 -S; }
route_lan() { ip route del default 2>/dev/null; ip route add default via 10.77.1.254; }
route_srv() { ip route del default 2>/dev/null; ip route replace 10.77.1.0/24 via 10.77.2.254; }
# služba běží ve smyčce; porucha = soubor /tmp/stop + ukončení procesu, obnova = smazání souboru
keep() { while true; do [ -f /tmp/stop ] || "$@"; sleep 1; done; }
dns_local() { echo "nameserver 10.77.2.53" > /etc/resolv.conf; }
