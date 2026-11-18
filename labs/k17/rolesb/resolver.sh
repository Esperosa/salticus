# Rekurzivní resolver pro lab B: stub zóny míří na vlastní tunelové autority a lab zóny na nsd.
{
cat <<'CFG'
server:
  interface: 0.0.0.0
  access-control: 10.88.0.0/16 allow
  username: ""
  chroot: ""
  use-syslog: no
  verbosity: 1
  do-not-query-localhost: no
  local-zone: "test." nodefault
  local-zone: "10.in-addr.arpa." nodefault
  domain-insecure: "test"
  domain-insecure: "10.in-addr.arpa"
stub-zone:
  name: "t1.lab.test"
  stub-addr: 10.88.0.21
stub-zone:
  name: "t2.lab.test"
  stub-addr: 10.88.0.22
stub-zone:
  name: "t3.lab.test"
  stub-addr: 10.88.0.23
CFG
for z in lab.test cdn.test avqs.test bl.test s1.test slow.test x1.test x2.test x3.test x4.test x5.test x6.test 88.10.in-addr.arpa; do
  printf 'stub-zone:\n  name: "%s"\n  stub-addr: 10.88.0.54\n' "$z"
done
} > /etc/unbound/unbound.conf
exec unbound -d -c /etc/unbound/unbound.conf
