# Studie 14B: provozní telemetrie (C2): signály poruch z primárních zdrojů

Stav 2026-11-15. Podle `00-protokol.md` (v1.0). Podklady: `14-provozni-telemetrie/extrakce.csv` (37 řádků, id `P14-xxx`), `hledani.csv`, `neovereno.md`, `matice-typ-signaly-zdroj.md` (75 typů). Doplňuje studii 13 (`13-katalog-provoznich-incidentu.md`), jejíž texty o projevech jsou podle jejího vlastního přiznání autorský souhrn bez ověřeného zdroje. Tady se k nim hledají primární zdroje (RFC, MIB, dokumentace).

Odchylky od zadání, které je nutné znát: (1) V RFC 5905 je STEPT **125 ms** a MAXDIST **1 s** (zadání uvádělo 128 ms a 1,5 s); uvádím hodnoty z RFC (P14-011). (2) Nezávislá kontrola podle §9 protokolu **nebyla provedena**. (3) Prahy z Prometheus a Zabbix jsou komunitní nebo produktové výchozí hodnoty, ne normy; značím je E5 nebo E4.

## 1. Abstrakt

- Standardní SNMP veličiny pro poruchy L1 a L2 existují a jsou definované v RFC: `ifOperStatus` (7 stavů), `ifInErrors`, `ifInDiscards`, `ifSpeed` (max 4 294 967 295 bit/s, pak `ifHighSpeed` v Mbit/s), `dot3StatsFCSErrors`, `dot3StatsDuplexStatus`, `sysUpTime` (setiny sekundy), `dot1dStpTopChanges` (P14-001 až P14-006). RFC **neuvádějí prahy ani typické hodnoty**; ty jsou jen v NMS a komunitních pravidlech.
- Referenční prahy etablovaných NMS: Zabbix `{$IF.ERRORS.WARN}`=2, `{$IF.UTIL.MAX}`=95, ICMP loss 20 %, ICMP odezva 0,15 s (P14-031); Prometheus komunitní: chyby rozhraní > 1 % paketů 2 min, využití > 80 % rychlosti, clock skew > 50 ms 10 min, disk a paměť < 10 %, conntrack > 80 % (P14-023).
- Čas: NTP STEPT 125 ms, PANICT 1000 s, WATCH 900 s; na LAN stovky mikrosekund, po internetu desítky milisekund (P14-011); Kerberos toleruje typicky 5 minut (P14-014). Z toho plyne, že 50 ms a 0,5 s jsou ladicí, ne normativní hranice.
- Certifikáty: komunitní alert 20 dní (warning) a 3 dny (critical) (P14-025); Let's Encrypt míří na 64 dní (2027-02-10) a 45 dní (2028-02-16), obnova po dvou třetinách životnosti (P14-026): pevné dny proto nestačí.
- DHCP: T1 = 0,5 a T2 = 0,875 délky zápůjčky (P14-015); ARP konflikt = stejná IP s jinou MAC (P14-018, P14-019); ND stavy a konstanty 30 000 ms REACHABLE_TIME (P14-020).
- Replikace a zálohy: PostgreSQL lag je interval a po dohnání se **změní na NULL** (P14-027); MySQL `Seconds_Behind_Source` je 0, když se nic nezpracovává, a NULL když applier neběží (P14-028).
- Odlišení poruchy od útoku: NMS dělají topologickou deduplikaci (Nagios DOWN vs UNREACHABLE, P14-033) a odlišují symptom od příčiny (P14-034, P14-035). Pro webové přetížení existuje empirický rozlišovač: dříve viděné klientské clustery tvoří u flash crowd 42,7 až 82,9 %, u útoků 0,1 až 14 % (P14-036). Cloudflare 2025-11-18 zprvu mylně tipoval DDoS u poruchy konfigurace (P14-037). **Systematický přehled, jak AIOps odlišuje poruchu od útoku, jsem nenašel.**

## 2. Metodika a PRISMA

| krok | počet |
|---|---:|
| záznamů v `hledani.csv` | 20 (9 WebSearch, 11 dávek WebFetch) |
| výsledků vyhledávání vrácených (součet) | 172 |
| stránek skutečně otevřených (součet pole „prohlíženo“) | 40 |
| zahrnuto do extrakce | 37 řádků (z ≈ 37 zdrojů, RFC 3433 a komunitní pravidla pro dva exportery počítám jako součást řádků) |
| V3 / V2 / V1 | 36 / 1 / 0 |

Odchylky: protokol žádá 15 dotazů na RQ a 3 dotazy „proti“; zde 9 vyhledávacích dotazů a 2 „proti“ (DDoS vs flash crowd, NOC/SOC chybná klasifikace). U dlouhých RFC jsem četl jen prvních 100 000 znaků (nebo cílený úsek přes offset), takže ostatní část RFC nebyla zhodnocena. Hodnoty z WebFetch u RFC jsou citace z odpovědi nástroje; kde stojí „parafráze“, nejde o doslovný text. WebFetch u stránek Microsoftu (w32tm, Kerberos) vrátil 404 a u Cisco Community 403.

## 3. Signály podle zdroje

Sloupce: veličina, jednotky, typické hodnoty a prahy z dokumentace, jaký typ poruchy indikuje, odkaz (id řádku v `extrakce.csv`). „RFC neuvádí“ znamená, že hodnota není součástí čteného textu.

### 3.1 SNMP

| veličina | jednotky | typické hodnoty a prahy | indikuje | odkaz |
|---|---|---|---|---|
| IF-MIB `ifOperStatus` | enum 1 až 7: up, down, testing, unknown, dormant, notPresent, lowerLayerDown | trap linkDown těsně před vstupem do down, linkUp těsně po opuštění; nikdy pro přechod z/do notPresent; prahy RFC neuvádí | výpadek linky, portu, switche, uplinku; flapping při opakování | P14-001 |
| `ifLastChange` | setiny s (sysUpTime) | hodnota sysUpTime při vstupu do stavu; ze dvou čtení lze odvodit flap | flapping | P14-003 |
| `ifInErrors` | pakety (čítač) | pakety s chybou bránící doručení; RFC prahy neuvádí; Zabbix `{$IF.ERRORS.WARN}`=2 (jednotka neověřena); Prometheus komunitní: chyby/pakety > 0,01 po 2 min | CRC, duplex, kabel, degradace linky | P14-002, P14-031, P14-023 |
| `ifInDiscards` | pakety | zahozeno bez chyby, typicky buffer | saturace, QoS | P14-002 |
| `ifSpeed`, `ifHighSpeed` | bit/s, Mbit/s | ifSpeed max 4 294 967 295; Zabbix `{$IF.UTIL.MAX}`=95 %; Prometheus komunitní > 80 % | saturace uplinku; pokles rychlosti linky při autonegotiaci | P14-003, P14-031, P14-023 |
| EtherLike `dot3StatsFCSErrors`, `AlignmentErrors`, `LateCollisions`, `ExcessiveCollisions` | rámce (čítač) | diskontinuity po re-inicializaci a podle ifCounterDiscontinuityTime; RFC prahy neuvádí | duplex mismatch, kabel, CRC | P14-004 |
| `dot3StatsDuplexStatus` | enum unknown(1), halfDuplex(2), fullDuplex(3) | | duplex mismatch (jedna strana half) | P14-004 |
| `sysUpTime` | setiny s | pokles = restart síťové správy; Zabbix trigger „Host has been restarted“ při poklesu uptime | restart, panic, firmware, výpadek napájení | P14-005, P14-031 |
| BRIDGE-MIB `dot1dStpTopChanges`, `TimeSinceTopologyChange` | čítač, setiny s | MaxAge 6 až 40 s, Hello 1 až 10 s, Forward Delay 4 až 30 s (rozsahy); trapy volitelné | smyčka L2, STP topology change, flapping linky | P14-006 |
| ENTITY-MIB, ENTITY-SENSOR-MIB | entPhysicalClass; celsius(8), voltsDC(4), rpm(10); operStatus ok/unavailable/nonoperational | prahy RFC neuvádí | napájení, ventilátor, teplota, rozbitý senzor | P14-007 |
| Dostupnost agenta | trigger | Zabbix: žádná SNMP data podle `zabbix[host,snmp,available]`; nedostupný ICMP při `max(icmpping,#3)=0`; ICMP loss > 20 % (5 min minimum, < 100 %); odezva > 0,15 s (5 min průměr) | výpadek zařízení vs. výpadek monitoringu (SNMP timeout při živém ICMP) | P14-031 |

### 3.2 Syslog

| zpráva nebo pole | význam a prahy | indikuje | odkaz |
|---|---|---|---|
| RFC 5424 severity | 0 Emergency až 7 Debug; facility mj. 0 kernel, 4 security/authorization, 12 NTP, 13 log audit | třídění závažnosti, filtr podle facility | P14-008 |
| RFC 5424 TIMESTAMP | RFC 3339; NILVALUE bez času; nesynchronizovaný originátor má uvést timeQuality | zdroj nejistoty při korelaci s toky | P14-008 |
| Cisco `%SW_MATM-4-MACFLAP_NOTIF` | „Host xxxx.xxxx.xxxx in vlan x is flapping between port (1) and port (2)“; nejčastěji smyčka L2, jinak vadný HW, SW chyba, MAC spoofing | smyčka L2, rogue/spoofing (nejednoznačné) | P14-030 |
| Linux `kernel.panic` | 0 = nekonečná smyčka, záporné = okamžitý restart, kladné = restart za N s; `hung_task_timeout_secs`, `softlockup_panic` | kernel panic, zamrznutí, restart smyčka | P14-029 |
| ISC dhcpd `no free leases` | podle V1 pool vyčerpán nebo žádný nabídnutelný lease | vyčerpání poolu (V1, `neovereno.md`) | neověřeno |
| Windows 41, 6008, 1074, 6006 a Cisco `LINK-3-UPDOWN`, `ROOTGUARD_BLOCK` | viz `neovereno.md` (V1) | | neověřeno |

### 3.3 NetFlow a IPFIX

| veličina | jednotky | poznámka | indikuje | odkaz |
|---|---|---|---|---|
| `octetDeltaCount` (ID 1), `packetDeltaCount` (ID 2) | oktety, pakety od předchozího reportu | RFC 7012 odkazuje definice do IANA | saturace, výpadek (pokles na nulu), DDoS | P14-010 |
| Sequence Number zprávy | modulo 2^32 záznamů | umožňuje zjistit zameškané Data Records | **ztráta exportu** vs. ztráta provozu | P14-009 |
| Template ID | 256 až 65 535 | kolektor nesmí předpokládat posloupnost | změna exportéru po restartu | P14-009 |
| `flowEndReason` (ID 136) | enum | hodnoty nečteny | idle vs active timeout | P14-010 (V3 jen definice), `neovereno.md` |

### 3.4 DHCP, ARP, ND

| veličina | hodnota z dokumentace | indikuje | odkaz |
|---|---|---|---|
| T1, T2 | 0,5 a 0,875 × délka zápůjčky | opakovaný renew = nestabilní server nebo cesta | P14-015 |
| DHCPNAK, DHCPDECLINE | NAK při nesplnitelném požadavku; DECLINE po zjištění použité adresy (např. ARP), server označí adresu za nedostupnou | duplicitní IP, nesprávný lease | P14-015 |
| vyčerpání poolu | server „may choose to report the problem to the system administrator“ | vyčerpání poolu | P14-015 |
| ISC `dhcpd.leases` | stav active/free, `abandoned` = nepřidělit znovu; změny se připisují na konec, platí poslední | vyčerpání, konflikty (abandoned) | P14-016 |
| Kea statistiky | `subnet[id].total-addresses`, `assigned-addresses`, `declined-addresses`, `v4-allocation-fail`, `pkt4-nak-sent`; popisy neověřeny | vyčerpání poolu: využití = assigned/total (moje definice) | P14-017 (V2) |
| ARP tabulka | nový záznam pro stejnou IP s jinou MAC „supersedes“ starý; stárnutí mimo rozsah RFC | konflikt IP, spoofing, výměna HW (nejednoznačné) | P14-018 |
| ACD (RFC 5227) | PROBE_NUM 3, PROBE_WAIT 1 s, ANNOUNCE_NUM 2, MAX_CONFLICTS 10, RATE_LIMIT_INTERVAL 60 s; probe má nulovou sender IP | duplicitní IP; probe není sken | P14-019 |
| ND stavy | INCOMPLETE, REACHABLE (30 000 ms), STALE, DELAY (5 s), PROBE; 3 solicitace po 1000 ms | nedostupný soused | P14-020 |
| Linux NUD | `failed` = „max number of probes exceeded without success“ | nedostupný soused, výpadek L2 | P14-021 |

### 3.5 Čas (NTP, chrony, Kerberos)

| veličina | jednotky | hodnoty a prahy | indikuje | odkaz |
|---|---|---|---|---|
| NTP offset, delay, dispersion, jitter | s | LAN: stovky µs; internet: desítky ms (poll do 36 h) | základ přesnosti hodin | P14-011 |
| Stratum | 0 až 16 | 16 = unsynchronized | ztráta synchronizace | P14-011 |
| STEPT, PANICT, WATCH | ms, s, s | 125 ms; 1000 s (démon skončí s diagnostikou); 900 s | skok hodin, vážná odchylka | P14-011 |
| Reach | 8bitový registr, v chronyc osmičkově | tři nuly = tři vynechané polly | nedostupný NTP server | P14-011, P14-012 |
| chrony `tracking` | System time, Last offset, RMS offset [s]; Frequency, Skew [ppm]; Leap status Normal/Insert/Delete/Not synchronised | | drift, ztráta synchronizace | P14-012 |
| `check_ntp_time -w -c` | s | příklad 0,5 a 1 (ilustrační, bez defaultu) | drift | P14-013 |
| Prometheus komunitní | s | skew > 0,05 s a rostoucí 10 min; nesynchronizace při maxerror ≥ 16 s | drift, nesynchronizace | P14-023 |
| Kerberos | s | typicky řádově 5 min; KRB_AP_ERR_SKEW | selhání AD/Kerberos | P14-014 |

### 3.6 Health-check, certifikáty, zálohy, hosty

| veličina | prahy | indikuje | odkaz |
|---|---|---|---|
| `probe_success` (blackbox) | `== 0` po 1 min (komunitní) | selhání služby, health-check | P14-024, P14-025 |
| `probe_duration_seconds` | > 1 s po 1 min | pomalá služba | P14-025 |
| HTTP stav | `<= 199` nebo `>= 400` po 1 min | chyba aplikace/proxy/WAF | P14-025 |
| `probe_ssl_earliest_cert_expiry` | dny do expirace: 3 až < 20 = warning, < 3 critical, < 0 expired | expirace, chybný řetěz (tady jen expirace) | P14-025 |
| Doba platnosti certifikátu | 45 dní (profil 2026-05-13), 64 dní (od 2027-02-10), 45 dní (od 2028-02-16); obnova po 2/3 životnosti | prahy odvodit z podílu životnosti | P14-026 |
| PostgreSQL `write_lag`, `flush_lag`, `replay_lag` | interval; po dohnání NULL; `state` streaming/catchup | zpoždění replikace; NULL není porucha | P14-027 |
| MySQL `Seconds_Behind_Source` | s; 0 když nic nezpracovává; NULL při neběžícím applieru | zpoždění; 0 může skrývat výpadek receiveru | P14-028 |
| `node_exporter` | kolektory arp, netdev, filesystem, hwmon, timex, conntrack, thermal_zone aj. | host metriky | P14-022 |
| komunitní host pravidla | paměť < 10 % 2 min; disk < 10 % 2 min; conntrack > 80 % 5 min; OOM kill increase 30 min > 0; chyby rozhraní > 1 % | plný disk, paměť, NAT/conntrack, OOM | P14-023 |

### 3.7 Konvence stavů NMS

Nagios: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN; rozsah `[@]start:end` (alert mimo rozsah); perfdata `'label'=value[UOM];warn;crit;min;max` (P14-032). UNKNOWN (nezměřeno) je třeba odlišit od CRITICAL (změřeno špatně): v naší terminologii „nevím“ vs „porucha“.

## 4. Jak NMS a AIOps rozlišují poruchu od útoku

Doloženo (V3):
1. **Topologická deduplikace.** Nagios označí hosty za DOWN rodičem jako UNREACHABLE a může potlačit jejich notifikace (P14-033). Hromadné zmizení hostů proto není nutně hromadná kompromitace (katalog OPS-001 uvádí právě tuto záměnu).
2. **Symptom vs příčina, black-box vs white-box.** Pager na symptom, příčinu hledat konzolemi (P14-034, P14-035).
3. **Vlastnosti klientů při přetížení webu.** Jung et al.: u flash crowd klienti ze stejných clusterů už dříve komunikovali (42,7 % Play-along, 82,9 % Chile), u Code Red jen 0,6 až 14 % a u password cracking 0,6 % a 0,1 %; rozdělení požadavků na soubory je Zipf-like; per-client rate je v FE nižší; Code Red: každý cluster přesně 3 nebo 6 požadavků za minutu (P14-036). Ověřeno na pěti webových logech z roku 2002 (E3), tedy staré a jen webové.
4. **Periodicita chyb jako stopa poruchy.** Cloudflare: kolísající chyby vypadaly jako útok; příčinou byl soubor generovaný každých 5 minut (P14-037).

Nenalezeno: systematický přehled nebo měření, jak AIOps odlišuje poruchu od útoku (shrnutí vyhledávače ukázalo přehledy AIOps pro poruchy bez bezpečnostní větve; viz `neovereno.md` #19, #20). Vendor tvrzení o NOC/SOC konvergenci jsou V1.

Z toho plyne (extrapolace): rozhodovací prvky pro Skákavku jsou (a) kořenová příčina podle topologie (kdo je rodič), (b) skutečnost „klient dříve neviděn“ jako prvek útoku proti flash crowd, (c) periodicita s přesnou periodou jako indicie poruchy generátoru nebo konfigurace, ale také jako beaconing (katalog OPS-002 říká, že flapping připomíná beaconing), proto nejednoznačné, (d) souběh signálů ze zdrojů, které útočník nekontroluje (SNMP z infrastruktury).

## 5. Matice typ → signály → zdroj důkazu (75 typů)

Plná tabulka je v `14-provozni-telemetrie/matice-typ-signaly-zdroj.md`, generovaná programově z `data/incident-catalog.json` (verze 1.0.0): pro každý z 75 typů obsahuje provozní signály (SNMP, syslog, DHCP, ARP, endpoint), síťové signály (toky, DNS, TLS), kanály důkazu, **automaticky přiřazenou** ověřenou veličinu s odkazem P14/E14 a záměnu s útokem podle katalogu.

Počty z katalogu: toky 75 typů, syslog 59, endpoint 52, TLS 36, SNMP 32, DNS 31, DHCP 15, ARP 12. Kategorie: porucha 56, neškodná změna 15, nejednoznačné 4. Pro 36 typů se klíčová slova na žádnou veličinu z této studie nenavázala (DNS, aplikace, VPN, cloud, QoS, trasování); to je mezera v rešerši, ne důkaz, že signál neexistuje.

Přehled po rodinách (mapování ID na rodinu je moje; signály ke každému ID jsou v matici):

| rodina | typy v katalogu | signály ověřené v této studii | kanály důkazu |
|---|---|---|---|
| fyzická a L2 linka | OPS-001, 002, 011, 013, 020, 044, 045, 062 | ifOperStatus, ifInErrors, dot3Stats*, dot1dStpTopChanges, MACFLAP, ifHighSpeed | SNMP, syslog, toky, ARP |
| DHCP a adresace | OPS-003, 004, 015, 036, 037, 038 | DHCP T1/T2, NAK/DECLINE, `abandoned`, ARP konflikt RFC 5227 | DHCP log, ARP, endpoint (APIPA) |
| čas | OPS-007, 008, 063 | NTP offset, stratum, reach, chrony, Kerberos skew 5 min | NTP, syslog, endpoint |
| certifikáty | OPS-009, 010, CHG-012 | `probe_ssl_earliest_cert_expiry`, životnost 45 až 64 dní | aktivní sonda, TLS |
| zálohy a replikace | OPS-012, 021, 052, CHG-004, CHG-009 | PostgreSQL lag, `Seconds_Behind_Source`, disk < 10 % | logy, toky |
| hostitelé a služby | OPS-016, 017, 018, 019, 022, 025, 054, 064 | node_exporter (paměť, OOM, disk), probe_success, conntrack | agent, aktivní sonda |
| restart a firmware | OPS-049, 050, CHG-003, CHG-014 | sysUpTime, kernel.panic, hung_task | SNMP, syslog, endpoint |
| monitoring samotný | OPS-027, CHG-006 | SNMP timeout při živém ICMP, IPFIX Sequence Number, UNKNOWN stav | monitoring |
| nejednoznačné s útokem | OPS-034, 036, 048, 059 | MACFLAP (smyčka vs spoofing), ARP supersedes (konflikt vs spoofing), flash crowd vs DDoS (P14-036) | více zdrojů |

## 6. Závěry

| Z-id | tvrzení | důkazy | jistota | důvody snížení | použitelnost | doporučená akce |
|---|---|---|---|---|---|---|
| Z14B-1 | Standardní SNMP veličiny pro L1/L2 poruchy jsou RFC; RFC nedávají prahy. | P14-001 až P14-006 | vysoká | čteno jen části dlouhých RFC | ano | normalizovat na rychlost růstu čítačů a změnu stavu, prahy z NMS |
| Z14B-2 | Referenční prahy NMS: Zabbix chyby 2, využití 95 %, ICMP loss 20 %, RTT 0,15 s; komunitní Prometheus chyby 1 %, využití 80 %, disk a paměť 10 %. | P14-031, P14-023 | střední | produktové výchozí hodnoty, ne měření; jednotka makra neověřena | s úpravou | kalibrovat na soaku; výchozí hodnoty brát jako startovní bod |
| Z14B-3 | Časové hranice: STEPT 125 ms, PANICT 1000 s, LAN stovky µs, internet desítky ms, Kerberos typicky 5 min. | P14-011, P14-014 | vysoká | část RFC nečtená; tolerance hodin hostu v praxi neměřena | ano | okno korelace ≥ rozlišení flow a odhad offsetu hostu |
| Z14B-4 | Pevné dny pro alert expirace certifikátu přestávají stačit (45 až 64 denní životnost). | P14-025, P14-026 | střední | termíny CA, komunitní prahy | ano | práh jako podíl životnosti |
| Z14B-5 | Zdánlivé „zdraví“ replikace lže: PostgreSQL lag NULL po dohnání, MySQL lag 0 při nečinnosti. | P14-027, P14-028 | vysoká | pouze dokumentace | ano | kombinovat lag se stavem vlákna |
| Z14B-6 | Mezera v IPFIX Sequence Number je ztráta exportu, ne ztráta provozu. | P14-009 | vysoká | část RFC nečtená | ano | oddělit „nevím“ od „nic“ |
| Z14B-7 | Topologická deduplikace (DOWN vs UNREACHABLE) a rozlišení symptom/příčina jsou standardní v NMS. | P14-033, P14-034, P14-035 | vysoká | dokumentace, ne měření | ano | rodič v topologii jako kořenová příčina |
| Z14B-8 | Klient „dříve neviděn“ odlišuje útok od flash crowd (0,1 až 14 % proti 42,7 až 82,9 %). | P14-036 | nízká až střední | 2002, jen web, žádná FPR | s úpravou | jako rys s vahou, ne pravidlo |
| Z14B-9 | Kolísavá chyba s periodou 5 minut může být porucha generátoru, ne útok. | P14-037 | nízká | jedna kauza | s úpravou | periodicita jako nejednoznačný rys |
| Z14B-10 | MAC flapping je nejčastěji smyčka L2, ale shodná zpráva nastane i při spoofingu. | P14-030 | střední | dokumentace výrobce | ano | korelovat s TopChanges |

## 7. Překlad do praxe

1. Každý signál v modelu nese `{zdroj, jednotka, typ čítače (stav, čítač, gauge), čas měření, kvalita času}`. Čítače převést na rychlost (delta/Δt) s ošetřením přetečení a diskontinuity (ifCounterDiscontinuityTime) [důkaz P14-004, P14-003].
2. Chybějící hodnota se vede jako `nevím` (UNKNOWN), ne `0` ani `porucha` [důkaz P14-032, P14-009, P14-027, P14-028].
3. Počáteční prahy: viz §3; jako startovní bod, kalibrovat per prostředí [Z14B-2; extrapolace: kalibrace na soaku, postup v §8].
4. Alert na certifikát: `zbývá < ⅓ životnosti` jako varování, `< 3 dny` jako kritické [extrapolace z P14-026 a P14-025].
5. Čas: pro každý zdroj `kvalita_času` z NTP stratum/offset nebo syslog timeQuality; okno korelace jako v studii 14A §6 [extrapolace].
6. Kořenová příčina podle topologie: nadřazený uzel DOWN → podřízené jako UNREACHABLE, nikoli samostatné nálezy [P14-033].
7. Nejednoznačné typy (OPS-034, 036, 048, 059): povinné nezávislé ověření, protože signál z jednoho zdroje nerozliší poruchu a útok [P14-030, P14-018, P14-036].
8. Nedokládané položky z katalogu (36 typů bez přiřazené veličiny) rozšířit o další rešerši (DNS, VPN, cloud, QoS).

## 8. Hypotézy k empirickému ověření (soak harness)

Kontext (`docs/diplomka/eval/soak-findings.md`): 6,55 M behaviorálních nálezů bez příčiny = 210,7 na síť a den; benigní lookalike: flash_crowd 56 441 nálezů, backup 31 368, authorized_scanner 5 824, ntp_fanout 4 142, software_update 0; 75 % nálezů tvoří `inductive_volume_anomaly`. Literatura tato čísla přímo nepotvrzuje; nejbližší je rozlišení flash crowd od útoku (P14-036) a topologická deduplikace (P14-033).

| H | změna | očekávaný efekt | metrika | scénář a seedy | kritérium zamítnutí |
|---|---|---|---|---|---|
| H14B-1 | kořenová příčina podle topologie (rodič DOWN potlačí potomky) | méně samostatných nálezů při výpadku uzlu (Nagios P14-033); velikost efektu není v literatuře | počet nálezů na výpadek, počet falešně zavřených | výpadek switche v simulaci (OPS-001), 10 seedů × 3 sítě | falešně zavřený útok > 0 nebo žádné snížení počtu nálezů |
| H14B-2 | rys „klient dříve neviděn“ pro flash_crowd vs DDoS | rozdělení 42,7 až 82,9 % vs 0,1 až 14 % [P14-036] | AUC rysu, FPR při TPR 0,95 | flash_crowd (56 441 nálezů v soak v1) vs ddos_volume | AUC < 0,8 na držených seedech |
| H14B-3 | práh certifikátu jako podíl životnosti | méně falešných varování u 45denních certifikátů | počet varování, zmeškané expirace | scénář OPS-009 s různou životností | zmeškané expirace > 0 |
| H14B-4 | IPFIX Sequence Number jako nezávislý příznak ztráty exportu | oddělí ztrátu exportu od ztráty provozu | podíl správně klasifikovaných ztrát | simulace ztráty exportu | záměna > 5 % |
| H14B-5 | UNKNOWN místo 0 při chybějícím čítači | méně falešných poruch při výpadku polleru (OPS-027) | falešné nálezy při výpadku monitoringu | scénář OPS-027 | nárůst přehlédnutých poruch |
| H14B-6 | NTP offset jako nejistota času u párování toků | menší počet špatně spárovaných událostí při driftu | podíl špatných párování | OPS-008 s driftem 50 ms až 5 min | zlepšení < 5 p.b. |

## 9. Hrozby validity

- RFC definují veličiny, nikoli typické hodnoty; typické prahy jsou z NMS a komunitních sbírek (P14-023, P14-025, P14-031), tedy nižší důkazní síla (E4, E5).
- Většina čtení je dokumentace, ne měření chování zařízení; jistota „vysoká“ platí jen pro znění dokumentu.
- Dlouhá RFC čtena jen z části (100 000 znaků, offsety); text mohl obsahovat upřesnění v nečtené části.
- Tabulka typ→signál je automatická podle klíčových slov a vychází z katalogu, který sám přiznává `basis: assumption` u 68 z 75 typů.
- Jung et al. je z roku 2002 a týká se jen webu; Cloudflare je jedna událost.
- Komunitní prahy Prometheus mohou být přizpůsobené jiným prostředím (autoři sami: „Alert thresholds depend on the nature of your applications“).

## 10. Co NEBYLO nalezeno

- Primární zdroje pro syslog zprávy Cisco `LINK-3-UPDOWN`, root guard, `PM-4-ERR_DISABLE`, Windows události 41, 6008, 1074 (jen V1, `neovereno.md`).
- Popisy statistik Kea a zprávy ISC dhcpd z oficiální dokumentace.
- Hodnoty `flowEndReason`, NetFlow v5/v9 timeouty a čítače, SNMP Counter64.
- Zabbix trigger pro snížení rychlosti Ethernetu a jednotky maker.
- Systematický přehled nebo měření, jak AIOps odlišuje poruchu od útoku.
- Měření falešných poplachů provozních signálů (FPR prahů) na reálných datech.
- Nezávislá kontrola podle §9 protokolu.
