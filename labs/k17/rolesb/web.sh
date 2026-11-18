mkdir -p /run/nginx /etc/nginx/http.d /www
rm -f /etc/nginx/http.d/default.conf  # výchozí server alpine koliduje s default_server níže
head -c 4000000 /dev/urandom | base64 > /www/blob
cat > /etc/nginx/http.d/lab.conf <<'CFG'
server { listen 80 default_server; root /www; location / { return 200 "ok\n"; } location /blob { } }
CFG
exec nginx -g 'daemon off;'
