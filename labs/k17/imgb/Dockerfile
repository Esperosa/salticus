# Krok 17, laboratoř B: obraz s nástroji DNS tunelu (iodine z apk, dnscat2 ze zdroje).
# Jen veřejné balíčky a veřejný zdroj dnscat2; žádná registrace ani osobní údaje.
FROM k17lab:1
RUN apk add --no-cache iodine git ruby-bundler \
 && git clone --depth 1 https://github.com/iagox86/dnscat2.git /opt/dnscat2 \
 && make -C /opt/dnscat2/client \
 && cd /opt/dnscat2/server && bundle install
CMD ["sleep", "infinity"]
