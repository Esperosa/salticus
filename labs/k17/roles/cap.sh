# zachytávání na rozhraní lan směrovače (obdoba SPAN přístupového uplinku), rotace po 10 min
sleep 3
LAN=$(ip -o -4 addr show | awk '/10\.77\.1\.254/{print $2}')
mkdir -p /out/pcap
exec tcpdump -i $LAN -s 256 -n -w /out/pcap/lan-%Y%m%d%H%M%S.pcap -G 600 -Z root not port 514
