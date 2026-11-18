. /lab/common.sh
start_syslog; route_lan
keep dnsmasq -k --port=0 --log-facility=- --dhcp-range=10.77.1.200,10.77.1.205,255.255.255.0,2m --dhcp-option=3,10.77.1.254 --dhcp-option=6,10.77.2.53 --dhcp-leasefile=/tmp/leases 2>&1 | logger -t dnsmasq-dhcp
