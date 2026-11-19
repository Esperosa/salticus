# směrovač mezi lan, srv a wan; nic mimo 10.77.0.0/16
ip route del default 2>/dev/null
iptables -A FORWARD ! -d 10.77.0.0/16 -j DROP
iptables -A FORWARD ! -s 10.77.0.0/16 -j DROP
ip -o -4 addr show | awk '/10\.77\.1\.254/{print $2}' > /tmp/lan_if
exec sleep infinity
