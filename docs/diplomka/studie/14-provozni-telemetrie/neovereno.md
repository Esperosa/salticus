# Studie 14B (provozní telemetrie): neověřeno (V1/V0)

Datum 2026-11-15. Co je tady, nesmí být v závěrech.

| # | tvrzení | úroveň | důvod |
|---|---|---|---|
| 1 | Cisco `%LINK-3-UPDOWN` je závažnost 3 a hlásí změnu stavu rozhraní; `%LINEPROTO-5-UPDOWN` hlásí protokol zvlášť | V1 | jen shrnutí vyhledávače; guide platformy nenačten |
| 2 | Cisco `%SPANTREE-2-ROOTGUARD_BLOCK`: root guard blokuje port, který dostal lepší BPDU; obnova automaticky | V1 | stránka Cisco Community vrátila 403; vyhledávač vrátil jen shrnutí |
| 3 | Cisco `%PM-4-ERR_DISABLE`: port v err-disabled po BPDU guard nebo port-security | V0 | výsledek vyhledávače přiznal, že jde o obecnou znalost; zdroj nenalezen |
| 4 | Windows události 41 (Kernel-Power), 6008 (neočekávané vypnutí), 1074 (iniciované vypnutí), 6006 (čisté vypnutí) | V1 | jen komunitní Q&A a třetí strany; oficiální stránka Microsoftu nenalezena |
| 5 | Linux text „Kernel panic - not syncing“ | V0 | stránka sysctl ho nepopisuje (ověřeno), samostatná dokumentace nenačtena |
| 6 | ISC dhcpd zprávy `DHCPDISCOVER ... no free leases`, `DHCPNAK` v syslogu; „no free leases“ neznamená prázdný pool, ale žádný lease nabídnutelný tomu klientovi | V1 | jen mailing list dhcp-users a blogy; KB aa-00334 se týká jiného tématu |
| 7 | Kea: popisy statistik `subnet[id].total-addresses`, `assigned-addresses`, `declined-addresses`, `v4-allocation-fail`, `pkt4-nak-sent` | V1 | názvy viděny v příkladu `statistic-get-all` (P14-017 V2), ale sekce Statistics se v načtených částech nenašla |
| 8 | Zabbix: triggery pro rychlost rozhraní „Ethernet has changed to lower speed“, „High error rate“ a výrazy s `{$IF.ERRORS.WARN}` | V1 | stránka načtena jen do 100 000 znaků ze 339 467; jednotky maker (paketů/s?) neověřeny; příklad z jiných šablon (TrueNAS) jen z vyhledávače |
| 9 | Zabbix trigger dependencies (potlačení závislých triggerů) | V0 | dokumentace vrátila 404; analogie Nagios reachability je V3 (P14-033) |
| 10 | Let's Encrypt e-maily o expiraci (20, 10, 1 den) | V0 | nepotvrzeno; vyhledávač uvádí, že Let's Encrypt e-maily zrušil (2025) |
| 11 | CA/Browser Forum: maximální platnost 398 dní, plánované 200 (2026), 100 (2027), 47 dní (2029) | V1 | stránka CA nezmiňuje schéma, jen sekundární blogy; text ballotu nečten |
| 12 | RFC 5905: STEP 128 ms (v zadání) | V0 | v RFC je STEPT 125 ms (P14-011), 128 ms se v čteném textu nevyskytlo |
| 13 | RFC 5905: MAXDIST 1,5 s (v zadání) | V0 | v RFC je MAXDIST 1 s (P14-011) |
| 14 | w32tm výstup (Phase Offset aj.), Kerberos „Maximum tolerance for computer clock synchronization“ = 5 min v dokumentaci Microsoftu | V0 | obě stránky Microsoftu vrátily 404; typicky 5 min je z RFC 4120 (P14-014) |
| 15 | Prometheus `node_exporter`: názvy metrik `node_network_receive_errs_total`, `node_timex_offset_seconds` | V1 (názvy z výrazů pravidel P14-023, V3 jako součást výrazů), popisy metrik nečteny | README uvádí jen kolektory |
| 16 | `probe_ssl_earliest_cert_expiry` popis | V1 | README blackbox_exporter ho neuvádí; použit z výrazu pravidla P14-025 |
| 17 | Variace IPFIX: hodnoty `flowEndReason` (idle timeout, active timeout, end of flow, forced end, lack of resources) | V0 | IANA stránka hodnotu tabulky v čteném rozsahu neobsahovala |
| 18 | NetFlow v5/v9 čítače a export timeouty (active 30 min / inactive 15 s) | V0 | nečteno; RFC 3954 nenačten |
| 19 | AIOps přehledy (Cheng et al. 2304.04661, Zhang et al. 2406.11213, Notaro et al.) | V1 | jen shrnutí vyhledávače; žádný z nich podle shrnutí neřeší odlišení poruchy od útoku |
| 20 | Julisch 2003: Clustering intrusion detection alarms to support root cause analysis | V0 | jen citace v seznamu literatury jiného přehledu |
| 21 | Splunk, ExtraHop: izolované uzavření incidentu jako falešného poplachu v NOC i SOC; MTTD o 65 % kratší | V1 | tvrzení výrobců |
| 22 | NIST SP 800-61 Rev. 3, ITIL definice incidentu | V0 | nenačteno (stránka v předchozí relaci vypršela) |
| 23 | Zeek `dhcp.log`, `weird.log`, ARP/ND v Zeeku (Zeek skript `known_hosts`, `arp`) | V0 | nečteno |
| 24 | Typické chování SNMP polling (intervaly 60 s, 5 min), counter wrap Counter32 při 1 Gbit/s ≈ 34 s | V0 | výpočet autora existuje (2^32 oktetů·8 / 1e9 ≈ 34,4 s), ale RFC 2863 ho nečtená část textu nepotvrzuje; Counter64 (ifHCInOctets) z RFC 2863 nečteno |
| 25 | Synthetic health checks u hyperscalerů (AWS Route 53 health checks apod.) | V0 | nečteno |
