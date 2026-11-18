. /lab/common.sh
start_syslog; route_srv
ROLE=$1
mkdir -p /data /run/nginx /etc/nginx/http.d
rm -f /etc/nginx/http.d/default.conf  # výchozí server Alpine koliduje s default_server níže
[ "$ROLE" = primary ] && python3 /lab/certs.py
while [ ! -f /out/ca/ca.pem ]; do sleep 1; done
[ "$ROLE" = secondary ] && { sleep 2; python3 /lab/certs.py; }
cp /tmp/tls/valid.crt /tmp/tls/cur.crt; cp /tmp/tls/valid.key /tmp/tls/cur.key
cat > /etc/nginx/nginx.conf <<'CFG'
worker_processes 1;
error_log syslog:server=10.77.2.50:514,tag=nginx warn;
events { worker_connections 256; }
http {
  access_log off;
  proxy_connect_timeout 2s; proxy_read_timeout 5s;
  include /etc/nginx/http.d/*.conf;
}
CFG
cat > /etc/nginx/http.d/lab.conf <<'CFG'
server {
  listen 80 default_server; listen 443 ssl default_server;
  ssl_certificate /tmp/tls/cur.crt; ssl_certificate_key /tmp/tls/cur.key;
  server_name _;
  location / { proxy_pass http://127.0.0.1:8080; }
}
server {
  listen 80; listen 443 ssl;
  ssl_certificate /tmp/tls/cur.crt; ssl_certificate_key /tmp/tls/cur.key;
  server_name app.lab.test;
  location / {
    if (-f /tmp/app-moved) { return 503; }
    proxy_pass http://127.0.0.1:8080;
  }
}
CFG
cat > /etc/supervisord.conf <<'CFG'
[supervisord]
nodaemon=false
logfile=/tmp/supervisord.log
pidfile=/tmp/supervisord.pid
[unix_http_server]
file=/tmp/supervisor.sock
[rpcinterface:supervisor]
supervisor.rpcinterface_factory = supervisor.rpcinterface:make_main_rpcinterface
[supervisorctl]
serverurl=unix:///tmp/supervisor.sock
[program:app]
command=python3 /lab/app.py
autorestart=true
startsecs=3
startretries=100
CFG
touch /tmp/supervisord.log
(tail -F /tmp/supervisord.log 2>/dev/null | logger -t supervisord) &
supervisord -c /etc/supervisord.conf
cat > /etc/snmp/snmpd.conf <<'CFG'
agentaddress udp:161
rocommunity lab 10.77.0.0/16

CFG
snmpd -Lsd -C -c /etc/snmp/snmpd.conf
exec nginx -g 'daemon off;'
