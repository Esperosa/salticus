. /lab/common.sh
start_syslog; route_srv
cat > /etc/unbound/unbound.conf <<'CFG'
server:
  interface: 0.0.0.0
  access-control: 10.77.0.0/16 allow
  username: ""
  chroot: ""
  use-syslog: yes
  verbosity: 1
  log-servfail: yes
  do-not-query-localhost: no
  domain-insecure: "lab.test"
  local-zone: "test." nodefault
  module-config: "iterator"
stub-zone:
  name: "lab.test"
  stub-addr: 10.77.2.54
remote-control:
  control-enable: yes
  control-use-cert: no
  control-interface: 127.0.0.1
CFG
keep unbound -d -c /etc/unbound/unbound.conf
