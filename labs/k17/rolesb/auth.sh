# Autorita pro lab.test (A záznamy pro kontrolní provoz a reputační jména).
mkdir -p /run/nsd /etc/nsd/zones
cat > /etc/nsd/zones/lab.test.zone <<'Z'
$TTL 300
@ IN SOA ns.lab.test. admin.lab.test. ( 1 3600 600 86400 300 )
@ IN NS ns.lab.test.
ns IN A 10.88.0.54
web IN A 10.88.0.10
api IN A 10.88.0.10
files IN A 10.88.0.10
mail IN A 10.88.0.10
@ IN TXT "v=spf1 ip4:10.88.0.0/16 -all"
Z
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
exec nsd -d -c /etc/nsd/nsd.conf
