. /lab/common.sh
start_syslog; route_lan; dns_local
while [ ! -f /out/ca/ca.pem ]; do sleep 1; done
if [ "$1" = mon ]; then exec python3 /lab/mon.py; fi
printf '#!/bin/sh\nexit 0\n' > /tmp/noop.sh; chmod +x /tmp/noop.sh
udhcpc -i eth0 -s /tmp/noop.sh -S -b -t 3 -T 3 -A 5 -x hostname:$(hostname) >/dev/null 2>&1
# měření offsetu NTP (chronyd -Q nic nenastavuje), výstup do syslogu
(while true; do chronyd -Q -t 5 "server 10.77.2.123 iburst maxsamples 2" 2>&1 | logger -t chronyd; sleep 30; done) &
exec python3 /lab/client.py
