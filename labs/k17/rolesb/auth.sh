# Autorita pro lab.test a kontrolní/exfiltrační zóny (A, TXT, PTR, SRV, zástupné záznamy).
# Vše jen v síti laboratoře; jména napodobují tvar skutečného provozu (CDN, AV reputace, DNSBL).
mkdir -p /run/nsd /etc/nsd/zones
SOA='@ IN SOA ns.lab.test. admin.lab.test. ( 1 3600 600 86400 300 )'
cat > /etc/nsd/zones/lab.test.zone <<Z
\$TTL 300
$SOA
@ IN NS ns.lab.test.
ns IN A 10.88.0.54
web IN A 10.88.0.10
api IN A 10.88.0.10
files IN A 10.88.0.11
mail IN A 10.88.0.10
*.www IN A 10.88.0.10
*.www2 IN A 10.88.0.11
@ IN TXT "v=spf1 ip4:10.88.0.0/16 -all"
_spf IN TXT "v=spf1 ip4:10.88.0.0/24 ip4:10.88.1.0/24 -all"
_dmarc IN TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@lab.test"
selector1._domainkey IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Dbv8prpJ"
selector2._domainkey IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz9Ecw9qsqK"
google._domainkey IN TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC5lab"
_ldap._tcp.dc._msdcs IN SRV 0 100 389 ns.lab.test.
_kerberos._tcp.dc._msdcs IN SRV 0 100 88 ns.lab.test.
_ldap._tcp.default-first-site-name._sites.dc._msdcs IN SRV 0 100 389 ns.lab.test.
_gc._tcp IN SRV 0 100 3268 ns.lab.test.
_kpasswd._udp IN SRV 0 100 464 ns.lab.test.
Z
CONF='server:
  ip-address: 0.0.0.0
  username: ""
  zonesdir: "/etc/nsd/zones"
  pidfile: "/run/nsd/nsd.pid"
zone:
  name: lab.test
  zonefile: lab.test.zone
'
# zóny se zástupným záznamem (kontroly i exfiltrace jen jednosměrně, odpověď nenese data)
for z in cdn.test avqs.test bl.test s1.test slow.test x1.test x2.test x3.test x4.test x5.test x6.test; do
  cat > /etc/nsd/zones/$z.zone <<Z
\$TTL 60
$SOA
@ IN NS ns.lab.test.
@ IN A 10.88.0.10
* IN A 10.88.0.10
* IN TXT "ok"
Z
  CONF="$CONF
zone:
  name: $z
  zonefile: $z.zone
"
done
# reverzní zóna 10.88.0.0/16 (PTR pro kontrolní klienty)
{
  echo "\$TTL 300"; echo "$SOA"; echo "@ IN NS ns.lab.test."
  for a in 0 1; do for b in $(seq 1 120); do echo "$b.$a IN PTR host-$a-$b.lab.test."; done; done
} > /etc/nsd/zones/88.10.in-addr.arpa.zone
CONF="$CONF
zone:
  name: 88.10.in-addr.arpa
  zonefile: 88.10.in-addr.arpa.zone
"
printf '%s' "$CONF" > /etc/nsd/nsd.conf
exec nsd -d -c /etc/nsd/nsd.conf
