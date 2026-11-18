# dns2tcp server pro zónu t3.lab.test; prostředek "web" = HTTP na lab web (jen uvnitř labu).
cat > /etc/dns2tcpd.conf <<'CFG'
listen = 0.0.0.0
port = 53
user = nobody
chroot = /tmp
domain = t3.lab.test
resources = web:10.88.0.10:80
CFG
exec dns2tcpd -F -f /etc/dns2tcpd.conf
