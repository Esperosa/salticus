# CoreDNS s DoH: přijímá DNS-over-HTTPS na :443/dns-query, přeposílá na lab resolver.
mkdir -p /etc/coredns
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /etc/coredns/k.pem -out /etc/coredns/c.pem -days 90 -subj "/CN=doh.lab.test" 2>/dev/null
cat > /etc/coredns/Corefile <<'CFG'
https://.:443 {
  tls /etc/coredns/c.pem /etc/coredns/k.pem
  forward . 10.88.0.53
}
CFG
exec coredns -conf /etc/coredns/Corefile
