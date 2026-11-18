# iodine server: autoritativní pro t1.lab.test, tunel 10.99.1.0/24. Heslo jen lokální konstanta.
iperf3 -s -D >/tmp/iperf.log 2>&1 &
exec iodined -f -c -P labpass -n 10.88.0.21 10.99.1.1 t1.lab.test
