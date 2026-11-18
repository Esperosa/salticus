# Krok 17, laboratoř B: obraz s nástroji DNS tunelu (iodine z apk, dnscat2 a dns2tcp ze zdroje).
# Jen veřejné balíčky a veřejné zdroje; žádná registrace ani osobní údaje.
FROM k17lab:1
RUN apk add --no-cache iodine coredns git ruby-bundler autoconf automake \
 && git clone --depth 1 https://github.com/iagox86/dnscat2.git /opt/dnscat2 \
 && make -C /opt/dnscat2/client \
 && cd /opt/dnscat2/server && bundle install \
 && git clone --depth 1 https://github.com/alex-sector/dns2tcp.git /opt/dns2tcp \
 && cd /opt/dns2tcp && (test -x configure || autoreconf -fi) && ./configure CFLAGS="-O2 -fcommon" \
 && make && make install
CMD ["sleep", "infinity"]
