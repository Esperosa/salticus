. /lab/common.sh
start_syslog
ip route del default 2>/dev/null
iptables -A FORWARD ! -d 10.77.0.0/16 -j DROP
iptables -A FORWARD ! -s 10.77.0.0/16 -j DROP
LAN=$(ip -o -4 addr show | awk '/10\.77\.1\.254/{print $2}')
SRV=$(ip -o -4 addr show | awk '/10\.77\.2\.254/{print $2}')
echo "$LAN" > /tmp/lan_if; echo "$SRV" > /tmp/srv_if
# emulovaná WAN linka 20 Mbit/s obousměrně (trvale; saturace = zátěž, ne změna konfigurace)
tc qdisc replace dev $SRV root netem rate 20mbit limit 200
tc qdisc replace dev $LAN root netem rate 20mbit limit 200
cat > /etc/snmp/snmpd.conf <<'CFG'
agentaddress udp:161
rocommunity lab 10.77.0.0/16
sysLocation k17-lab
CFG
snmpd -Lsd -C -c /etc/snmp/snmpd.conf
mkdir -p /usr/arpwatch; touch /tmp/arp.dat
arpwatch -i $LAN -f /tmp/arp.dat -Q || arpwatch -i $LAN -f /tmp/arp.dat
exec sleep infinity
