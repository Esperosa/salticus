# rsyslog: příjem UDP 514, zápis RFC 5424 s IP odesílatele jako hostname.
. /lab/common.sh; route_srv
mkdir -p /out/logs
cat > /etc/rsyslog.conf <<'CFG'
module(load="imudp")
input(type="imudp" port="514")
template(name="k17" type="string" string="<%PRI%>1 %TIMESTAMP:::date-rfc3339% %FROMHOST-IP% %APP-NAME% %PROCID% - - %msg:2:$%\n")
*.* action(type="omfile" file="/out/logs/syslog.log" template="k17")
CFG
exec rsyslogd -n -f /etc/rsyslog.conf
