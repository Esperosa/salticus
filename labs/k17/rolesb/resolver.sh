# Rekurzivní resolver pro lab B: stub zóny míří na vlastní tunelové autority a lab.test na nsd.
cat > /etc/unbound/unbound.conf <<'CFG'
server:
  interface: 0.0.0.0
  access-control: 10.88.0.0/16 allow
  username: ""
  chroot: ""
  use-syslog: no
  verbosity: 1
  do-not-query-localhost: no
  domain-insecure: "lab.test"
  domain-insecure: "t1.lab.test"
  domain-insecure: "t2.lab.test"
  local-zone: "test." nodefault
stub-zone:
  name: "lab.test"
  stub-addr: 10.88.0.54
stub-zone:
  name: "t1.lab.test"
  stub-addr: 10.88.0.21
stub-zone:
  name: "t2.lab.test"
  stub-addr: 10.88.0.22
CFG
exec unbound -d -c /etc/unbound/unbound.conf
