. /lab/common.sh
start_syslog; route_srv
cat > /etc/chrony/chrony.conf <<'CFG'
local stratum 8
allow all
CFG
keep chronyd -d -x -f /etc/chrony/chrony.conf
