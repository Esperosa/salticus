# Klient tunelu/kontroly. $1 = iodine|dnscat|doh|control, $2 = štítek relace (soubor pcap).
# Sám zachytává svůj provoz (per-relace, čistý štítek); vše jen do labu.
MODE=$1; LABEL=${2:-$1}
echo "nameserver 10.88.0.53" > /etc/resolv.conf
mkdir -p /out/pcapb
tcpdump -i eth0 -s 0 -n -w /out/pcapb/$LABEL.pcap -Z root port 53 or port 443 >/dev/null 2>&1 &
CAP=$!
sleep 6
case "$MODE" in
  iodine)
    iodine -f -P labpass -r 10.88.0.53 t1.lab.test >/tmp/iodine.log 2>&1 &
    sleep 10
    for i in $(seq 1 "${ROUNDS:-1}"); do
      iperf3 -c 10.99.1.1 -t 60 -b 300k -l 1024 >/dev/null 2>&1 || true
      ping -c 40 -s 1000 10.99.1.1 >/dev/null 2>&1 || true
    done
    ;;
  dnscat)
    for i in $(seq 1 "${ROUNDS:-1}"); do
      timeout 150 /opt/dnscat2/client/dnscat --dns "server=10.88.0.53,domain=t2.lab.test" --secret=labsecret \
        --exec "sh -c 'head -c 1500000 /dev/urandom | base64'" 2>/dev/null || true
    done
    ;;
  doh)
    for i in $(seq 1 "${ROUNDS:-1}"); do
      for n in $(seq 1 300); do
        curl -s -k --doh-url https://10.88.0.70/dns-query "https://web.lab.test/" -o /dev/null \
          --resolve web.lab.test:443:10.88.0.10 2>/dev/null
        curl -s -k --doh-url https://10.88.0.70/dns-query -o /dev/null "http://api.lab.test/" 2>/dev/null
      done
    done
    ;;
  control)
    for i in $(seq 1 "${ROUNDS:-1}"); do
      for n in $(seq 1 300); do
        host=$(printf 'web\napi\nfiles\nmail\nns\n' | sed -n "$((RANDOM%5+1))p")
        nslookup -type=A $host.lab.test 10.88.0.53 >/dev/null 2>&1
        nslookup -type=TXT lab.test 10.88.0.53 >/dev/null 2>&1
        curl -s -o /dev/null "http://web.lab.test/" 2>/dev/null
        sleep 0.2
      done
    done
    ;;
esac
sleep 3
kill $CAP 2>/dev/null
sleep 2
