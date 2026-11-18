. /lab/common.sh
start_syslog; route_srv
mkdir -p /var/lib/nsd /run/nsd /etc/nsd/zones

cat > /etc/nsd/nsd.conf <<'CFG'
server:
  ip-address: 0.0.0.0
  username: ""
  zonesdir: "/etc/nsd/zones"
  pidfile: "/run/nsd/nsd.pid"
zone:
  name: lab.test
  zonefile: lab.test.zone
CFG
echo 10.77.2.10 > /tmp/app_ip
run_nsd() { sh /lab/zone.sh $(cat /tmp/app_ip) > /etc/nsd/zones/lab.test.zone; nsd -d -c /etc/nsd/nsd.conf; }
keep run_nsd
