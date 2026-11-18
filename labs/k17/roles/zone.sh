# zóna lab.test; $1 = adresa app.lab.test
cat <<Z
\$TTL 600
@ IN SOA ns.lab.test. admin.lab.test. ( $(date +%s) 3600 600 86400 600 )
@ IN NS ns.lab.test.
ns IN A 10.77.2.54
web IN A 10.77.2.10
app IN A $1
ntp IN A 10.77.2.123
files IN A 10.77.2.10
api IN A 10.77.2.10
Z
