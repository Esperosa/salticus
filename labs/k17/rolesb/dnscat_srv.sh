# dnscat2 server pro zónu t2.lab.test; výstup do /out, bez auto-příkazů.
cd /opt/dnscat2/server
exec ruby ./dnscat2.rb --dns "domain=t2.lab.test,host=0.0.0.0,port=53" --no-cache --security=open --secret=labsecret 2>&1
