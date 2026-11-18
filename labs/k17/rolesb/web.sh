mkdir -p /run/nginx /etc/nginx/http.d /www /etc/nginx/tls
rm -f /etc/nginx/http.d/default.conf  # výchozí server alpine koliduje s default_server níže
head -c 4000000 /dev/urandom | base64 > /www/blob
# HTTPS s vlastním certifikátem (jen lab); stránky malé, /blob velký, /api malá odpověď JSON
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout /etc/nginx/tls/k.pem -out /etc/nginx/tls/c.pem -days 90 -subj "/CN=web.lab.test" 2>/dev/null
cat > /etc/nginx/http.d/lab.conf <<'CFG'
server {
  listen 80 default_server;
  listen 443 ssl default_server;
  http2 on;
  ssl_certificate /etc/nginx/tls/c.pem;
  ssl_certificate_key /etc/nginx/tls/k.pem;
  keepalive_requests 10000;
  keepalive_timeout 300s;
  root /www;
  location / { return 200 "ok\n"; }
  location /api { default_type application/json; return 200 '{"status":"ok","items":[1,2,3]}\n'; }
  location /blob { }
}
CFG
exec nginx -g 'daemon off;'
