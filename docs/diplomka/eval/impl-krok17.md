# Krok 17: vlastní Docker laboratoř se skutečnými záznamy provozních poruch, DNS tunelu a DoH

Datum zahájení 2026-11-18. Výchozí stav: konec kroku 16 (commit `8ddcf45`). Zadání: `F:\claude-tmp\briefs\krok17-lab.txt`. Rozsah: `docs/diplomka/rozsah-autonomie.md`.

Proč: v kroku 15 (P3) se ukázalo, že projev poruchy v simulátoru a v katalogu vznikly nezávisle, takže klasifikaci poruch (C1 až C5) na simulaci ověřit nejde (krok 15: C1 67 %, C2 47 %, C4 a C5 22 %). Veřejné datasety DoH a DNS tunelu vyžadují formulář s osobními údaji, proto se nepoužijí. Řešení: vlastní laboratoř na tomto počítači, kde je štítek (typ poruchy, začátek, konec) dán skriptem, který poruchu vyvolal.

## Předregistrace (zapsáno před kódem laboratoře a měření)

### Laboratoř A: provozní poruchy

Docker Compose `labs/k17/` na tomto počítači, sítě typu `internal` (bez cesty ven, domácí síť se nedotýká): `lan` 10.77.1.0/24 (klienti c1 až c4, monitorovací host, DHCP server dnsmasq, směrovač), `srv` 10.77.2.0/24 (resolver unbound, autoritativní nsd, NTP chrony, webová aplikace nginx + aplikace pod supervisord s HTTPS, rsyslog, sběrač). Směrovač je kontejner s IP forwardingem, klienti mají výchozí trasu přes něj. Telemetrie (vše skutečné výstupy nástrojů, žádný text psaný autorem do logu): syslog přes busybox `syslogd -R` do rsyslog (RFC 5424, odesílatel jako IP), SNMP (`snmpd` ve směrovači a v aplikaci, sběrač `snmpget` s převodem čítačů na rychlosti a využití, jak to dělá Zabbix nebo Cacti), DHCP logy dnsmasq a klientů `udhcpc`, arpwatch na směrovači, `chronyd -Q` (měření offsetu NTP), health-check ve formátu Nagios (stav se hlásí při změně, HARD po 3 pokusech) a blackbox styl Prometheus. Zachytávání: `tcpdump` v síťovém jmenném prostoru směrovače na rozhraní `lan` (obdoba SPAN na přístupovém uplinku); zpracování `zeek -C -r`. Surové záznamy jen v `F:\Projekty\bakula-datasets\lab-k17\`, v repu skripty, konfigurace a statistiky.

Scénáře (slot 300 s: 100 s normální provoz, 100 s porucha nebo útok, 100 s normální provoz po obnově; okna přehrávání 100 s zarovnaná na fáze; zahřátí 180 s). Délka fáze (zapsáno před během) je dána stropem 2 h na jeden odpojený běh v tomto prostředí; 100 s fáze stačí: sběrač SNMP poll po 10 s (≥ 9 vzorků), Nagios dosáhne HARD při 3. pokusu (~30 s), tok poruchy je ustálený. Metodika se nemění. Očekávané `catalog_id` dané mechanismem poruchy, zapsané předem (v závorce přijatelné alternativy se stejným mechanismem):

| id | vyvolání | očekávaná třída | očekávané `catalog_id` |
|---|---|---|---|
| S01 dhcp_down | zastavení DHCP v dnsmasq | porucha | OPS-004 |
| S02 dhcp_pool | pool 4 adresy, 8 klientů (macvlan) žádá lease | porucha | OPS-003 |
| S03 dns_auth_down | zastavení autoritativního nsd (SERVFAIL) | porucha | OPS-005 |
| S04 dns_stale | přesun služby na jinou IP, resolver drží starý záznam (TTL) | porucha | OPS-029 |
| S05 dns_slow | `tc netem delay` na resolveru | porucha | OPS-006 |
| S06 link_loss | `tc netem loss` na rozhraní směrovače | porucha | OPS-020 (OPS-045, OPS-046) |
| S07 link_saturation | `tc tbf` omezení linky a hromadné stahování | porucha | OPS-011 |
| S08 mtu | menší MTU na směrovači a zahazování ICMP frag-needed | porucha | OPS-035 |
| S09 service_crash | opakované zabití aplikace, supervisord restartuje | porucha | OPS-016 (OPS-019, OPS-054) |
| S10 cert_expired | nginx s prošlým certifikátem | porucha | OPS-009 |
| S11 ntp_offset | NTP server s posunutým časem | porucha | OPS-008 |
| S12 ntp_down | zastavení NTP serveru | porucha | OPS-007 |
| S13 dup_ip | klient si přidá IP jiného klienta | porucha | OPS-015 |
| S14 new_device | nový kontejner v `lan` | zmena | CHG-013 |
| S15 disk_full | aplikace zaplní malý tmpfs | porucha | OPS-021 |
| K1 až K3 | bez poruchy | utok (bez provozního důkazu) | žádné |
| A1 nmap | `nmap -sS` sken podsítě `srv` z klienta | utok | žádné |
| A2 arp_spoof | otrávení ARP klienta (scapy, IP směrovače s MAC útočníka) | utok | žádné |
| A3 nmap + loss | A1 během S06 | utok pro nálezy o skeneru | žádné |

Nerealizováno a proč (předem): expirace leasů jako samostatný scénář (v kontejneru se projeví stejně jako S01, jen pomaleji), VLAN (Docker bridge nenese 802.1Q mezi kontejnery realisticky), plný disk na úrovni hostitele (sdílený disk VM Docker Desktop), posun hodin hostitele (sdílené hodiny VM; posun se dělá na serveru, ne u klienta).

Sady (seed určuje pořadí scénářů, postiženého klienta a velikost poruchy v předem daném rozsahu):

- **ladicí** (seed 17001): každý S jednou, K1 a K2, A1 až A3 (20 slotů). Smí se podle nich opravit parser (viz níže), nic jiného.
- **držená** (seed 17101): každý S jednou, K1 až K3, A1 až A3 (21 slotů), běží jednou po zmrazení kódu (commit zapsaný níže před během). Výsledek se hlásí, ať je jakýkoli.

### Laboratoř B: DNS tunel a DoH

Samostatný Compose: resolver unbound se stub zónami na vlastní autoritativní servery `iodined` (zóna `t1.lab.test`) a `dnscat2` server (zóna `t2.lab.test`), CoreDNS s DoH (`https://`) pro DoH klienta (`curl --doh-url`), kontrolní klienti s normálním DNS (A/AAAA pro jména v lab zóně, SPF/DKIM TXT dotazy, hashované štítky typu antivirové reputace s typem A) a HTTPS na lab web. iodine a dnscat2 přenášejí data (soubor 1 až 4 MB, interaktivní příkazy). Zachytávání pcap na rozhraní klientů, Zeek, produkční cesta `beh spust --zeek-dir` s `l7_dns,l7_tls`, detektory `dns_tunnel_names` a `dns_zone_enumeration` beze změny prahů.

Relace po 180 s (zahřátí 25 s; délka dána týmž stropem, pro tvar tunelu stačí — iodine pošle tisíce dotazů za minutu): ladicí sada iodine 1x, dnscat2 1x, DoH 1x, kontrola 1x; držená sada iodine 2x, dnscat2 2x, DoH 2x, kontrola 2x. iodine se spustí s typem dotazu NULL (`-T NULL`, nejvyšší propustnost, odpovídá tvaru, který detektor očekává); dnscat2 ve výchozím střídání TXT/CNAME/MX. Pro tunel je nutné zařízení `/dev/net/tun`; DoH klient curl potřebuje `--doh-insecure` kvůli vlastnímu certifikátu DoH serveru.

Očekávání zapsaná předem (hypotézy, ne cíle): iodine (výchozí typ NULL, dlouhé štítky) detektor tunelu zachytí; dnscat2 ve výchozím nastavení střídá TXT, CNAME a MX, takže podíl TXT/NULL bude pod 0,6 a detektor ho pravděpodobně mine; DoH je pro DNS detektory neviditelné (jen TLS na IP resolveru), pro něj detektor v produkci neexistuje.

### Měřená cesta

Produkční binárka, žádný zvláštní měřicí kód v rozhodování:

1. `ops ingest` (formáty syslog, snmp, prometheus, nagios, dhcp, arp) do pracovního prostoru po oknech s časem okna; jediná změna: `ops ingest` respektuje `SALTICUS_REPLAY_NOW` stejně jako `beh spust` (bez toho by signály dostaly čas zpracování, ne čas vzniku).
2. `beh spust --zeek-dir` pro každé okno se `SALTICUS_REPLAY_NOW` = **konec okna** (živý systém zpracuje okno, až skončí), jeden pracovní prostor na sadu (paměť a profil se učí přes celou sadu).
3. Vrstva diagnózy (M1): nový příkaz `ops diagnose` (produkční `load_store` + `diagnose` se stejnou politikou jako pipeline). **Oddělený sklad na slot**: každý slot S dostane vlastní pracovní prostor, do kterého se nahraje jen heartbeat zdrojů z konce zahřátí a telemetrie daného slotu (normál + porucha), ne telemetrie jiných slotů. Důvod: sloty běží po sobě v jedné laboratoři, ale provozní okno diagnózy jsou 3 h, takže by se signály sousedních slotů mísily a diagnóza jednoho slotu by viděla poruchy jiného; oddělený sklad odpovídá tomu, že každý incident se v praxi diagnostikuje proti telemetrii svého okna. Diagnóza se pak volá pro předem daný typ nálezu na postiženém hostu v čase konce poruchy: dostupnostní poruchy `service_unreachable` (S01 až S05, S09 až S13, S15), linkové `connection_timeout_burst` (S06 až S08), S14 `new_device` na novém hostu, A1 `scan_attempts` a `unexpected_traffic` na skeneru, A2 `unexpected_traffic` na útočníkovi i oběti, K `service_unreachable` na náhodné službě uprostřed slotu. Hosty: IP služby a postiženého klienta.
4. Konec do konce (M2): zobrazené nálezy v oknech poruchy, jejich `ops_diagnosis`; nálezy v oknech kontrol a útoků.

Ramena konfigurace: `ops` (`ops_telemetry`) a `k15ops` (+ `ops_symptoms`, `ops_blast`), obě nad `recommended()` + `l7_dns`, `l7_tls`. Prahy `DiagPolicy` a detektorů se v tomto kroku **nemění**.

### Prahy (převzaté z kroku 14, nesnižují se)

| práh | metrika | splněno, když |
|---|---|---|
| K17-C1 | správná třída `porucha`/`zmena` u slotů S (M1) | ≥ 85 % |
| K17-C2 | správné `catalog_id` (nebo předem uvedená alternativa) tam, kde laboratoř telemetrii daného typu skutečně dodala | ≥ 80 % |
| K17-C3 | stejné sloty S se skladem bez primárních zdrojů (SNMP a syslog vynechány při ingestu): „nelze určit, chybí telemetrie“ | ≥ 90 % a jisté zařazení ≤ 10 % |
| K17-C4 | útok zařazený jako porucha (A1 až A3, M1 i M2) | ≤ 5 % |
| K17-C5 | porucha zařazená jako útok (sloty S, M1) | ≤ 10 % |
| K17-C6 | kontroly K: diagnóza jiná než `utok`/bez důkazu | 0 |
| K17-T1 | detekce DNS tunelu na relaci (zobrazený nebo vytvořený `dns_tunnel_names`) | iodine ≥ 80 % relací; dnscat2 a DoH se hlásí bez prahu |
| K17-T2 | falešné poplachy `dns_tunnel_names` a `dns_zone_enumeration` na kontrolním provozu (laboratoř B i A) | 0 |

Při malém n se hlásí i Wilsonův interval; „splněno“ se posuzuje podle bodového odhadu, interval je informace o nejistotě. Nikde se netvrdí 100% detekce.

### Pravidla změn

- Povolené změny kódu: parsery formátů, které laboratoř skutečně produkuje a které adaptéry neznají (každý s fuzz testem: náhodné bajty a mutace řádků, nikdy panika), `ops ingest` s časem přehrávání, příkaz `ops diagnose`. Rozhodují se jen na ladicí sadě a zapíší se níže před drženým během.
- Zakázané: změna prahů diagnózy a detektorů, změna katalogu podle laboratoře, ladění na držené sadě.
- Kořenové příčiny selhání se zapíší po scénářích (parser chybí, signál chybí v katalogu, mechanismus nevede ke klíči, rozsah signálu nesedí na hosta).
- Běhy: Idle, maska 0x3FFFFC, nejvýš 8 vláken, dlouhé běhy odpojeně (`Start-Process` a čekání na PID). `CARGO_TARGET_DIR=F:/claude-tmp/target-k17`.

Hrozby validity zapsané předem: laboratoř staví a štítkuje autor kódu; malé n (1 slot na scénář a sadu); Docker Desktop sdílí jádro, hodiny a disk VM, takže některé poruchy jsou jen přiblížení; health-check a sběrač konfiguruje autor (formát výstupu je ale formát skutečného nástroje, ne vymyšlený text); motor je v krátké laboratoři „studený“ (zralost hostů 12 h), takže M2 podhodnocuje detekci chování.

## Dodatek D1: detektor DNS tunelu v2, detektor DoH a atypické varianty (zapsáno 2026-11-18 před změnou kódu)

### Proč (ladicí běh laboratoře B, `debugB4`)

Laboratoř B se rozběhla až po opravách (dnscat2 server bez TTY končil hned po startu a resolver vracel SERVFAIL; nginx kolidoval s výchozím serverem). Ladicí běh B4 (seed 17001, jedna relace na režim): iodine 1/1, dnscat2 0/1, DoH 0/1, kontrola 0 falešných poplachů. dnscat2 má 4 826 různých jmen, průměrná značka 60 znaků, entropie 3,79, ale podíl TXT/NULL jen 0,35, protože střídá TXT, CNAME a MX; pravidlo v1 vyžaduje ≥ 0,6. Předregistrované očekávání (dnscat2 mine) se potvrdilo. Kořenová příčina: rys „typ záznamu“ je definován úzce (jen TXT/NULL/PRIVATE) a tunel s typem A ho nesplní nikdy. Druhá slabina v1: délka a entropie se měří jen u nejlevější značky a průměrují se přes dotazy (opakování), ne přes různá jména.

### Detektor `dns_tunnel_names` v2 (`heuristika-behavior:l7-dns-tunnel@v2`)

Skupina = (vnitřní zdroj, základní zóna `zone_of`). Vynechá se provoz, který z principu nemůže nést tunel přes hranici sítě: jména pod `.local` a dotazy na adresy link-local multicast (mDNS 224.0.0.251, ff02::fb, LLMNR 224.0.0.252, ff02::1:3). Rysy, všechny přes **různá jména** U:

- `s` = část jména před zónou bez teček (celá zakódovaná část, ne jen první značka), `n_u` = |U|, `uniq` = |U| / počet dotazů,
- `L` = průměrná délka `s`, `H` = průměrná Shannonova entropie `s` (bity na znak),
- `R` = podíl dotazů s typem schopným nést data v odpovědi: TXT, NULL, PRIVATE, CNAME, MX, SRV, KEY, DNAME (A, AAAA, PTR, HTTPS/SVCB a SOA se nepočítají; HTTPS/SVCB posílají prohlížeče ke každému jménu),
- `B` = součet délek `s` přes U (zakódované bajty), `rate` = B / max(rozpětí času dotazů, 60 s).

Poplach, když platí **T1** (tvar + typ): `n_u ≥ 8`, `uniq ≥ 0,3`, `L ≥ 24`, `H ≥ 3,0`, `R ≥ 0,5`; nebo **T2** (tvar + objem, bez ohledu na typ, pro tunely typu A): `n_u ≥ 100`, `uniq ≥ 0,5`, `L ≥ 24`, `H ≥ 3,0`, `B ≥ 96 000` a `rate ≥ 1 000 B/s`. Nález uvádí, která větev zabrala, a všechny rysy. Každá větev kombinuje aspoň dva nezávislé rysy (tvar jména a typ, resp. tvar jména a objem). Prahy se smí ladit jen na ladicí sadě (seed 17001); změny se zapíší níže před drženým během.

### Detektor `doh_suspected` (`heuristika-behavior:l7-doh@v1`)

Jen metadata toků (`conn.log`), TLS (`ssl.log`: SNI, ALPN) a DNS, žádné dešifrování. Kandidát = (vnitřní host, vnější IP) s TCP na 443. Spouští se se `l7_tls`.

- **K** (známý resolver): IP nebo SNI ze seznamu veřejných DoH resolverů (Cloudflare, Google, Quad9, OpenDNS, AdGuard, NextDNS, CleanBrowsing), nebo TCP 853 (DoT) na vnější adresu. Stačí samo, závažnost nízká (obcházení firemního resolveru). V laboratoři se ověří jen jednotkovým testem (nic ven).
- **Tvar A** (spojení na dotaz): ≥ 10 spojení na kandidáta v okně, medián `orig_bytes` ≤ 2 500, medián `resp_bytes` ≤ 8 000, medián trvání ≤ 10 s.
- **Tvar B** (trvalé spojení s malými záznamy): spojení s trváním ≥ 30 s, `orig_pkts` ≥ 30, průměrně ≤ 300 B na paket od klienta a ≤ 600 B na paket od serveru.
- **C2** (mlčení resolveru, druhý nezávislý rys): host v okně kontaktoval ≥ 2 další vnější IP (mimo kandidáta, mimo port 53) a položil méně dotazů na port 53, než je těchto IP (cíle se zjevně neresolvují obyčejným DNS).

Poplach: K, nebo (tvar A nebo tvar B) a zároveň C2. SNI a ALPN se uvádějí v důkazech (chybějící SNI = přímá IP), do rozhodnutí nevstupují, protože je nemá každý zdroj. JA3 se nepoužije: Zeek 9 ho bez balíčku nepočítá. Poplachový pár se neučí.

Nový typ nálezu se zařadí stejně jako `dns_tunnel_names` (chráněný typ „novelty“, taktika command-and-control, kontrola protějšků ve žebříku).

### Rozšíření laboratoře B (před během, platí pro obě sady)

Měřená cesta stejná jako dosud, jen rozsah `--scope` při vyhodnocení je **síť klientů 10.88.1.0/24** (servery 10.88.0.x jsou pro klienta „venku“, jako resolver a weby u skutečného hosta; s rozsahem /16 by DoH server i weby byly vnitřní a pravidla pro odchozí provoz by se nevyhodnotila). Zachytávání u klienta: celé rozhraní (ne jen porty 53 a 443), aby byly vidět i spojení na weby. Nový `web2` (10.88.0.11) se stejným obsahem, oba weby i HTTPS (vlastní certifikát). Autorita `nsd` dostane zóny se zástupnými záznamy (`*.www.lab.test`, `*.cdn.test`, `*.avqs.test`, `*.bl.test`, `*.s1.test`, `*.slow.test`, `x1.test` až `x6.test`), reverzní zónu `88.10.in-addr.arpa`, DKIM, SPF, DMARC a SRV. dns2tcp se sestaví z veřejného zdroje (zóna `t3.lab.test`, server 10.88.0.23). Vlastní exfiltrační klient `exfil.py` (UDP dotazy na resolver, data z `/dev/urandom` v base32) pro varianty, které nástroje neumí.

Relace (tunely a DoH jsou pozitivní, kontroly negativní):

| režim | popis |
|---|---|
| iodine | `-T NULL` (původní) |
| iodine-txt, iodine-cname, iodine-mx, iodine-a | `-T TXT`, `CNAME`, `MX`, `A` |
| dnscat | výchozí střídání TXT/CNAME/MX (původní) |
| dnscat-txt, dnscat-cname, dnscat-mx, dnscat-aaaa | `--dns ...,type=X` (odchylka před během: `type=A` přes resolver unbound relaci nenaváže, unbound přeuspořádá sadu záznamů A a klient hlásí „DNS didn't return an answer“; přímo na server funguje. Varianta s adresním typem se proto měří jako `type=AAAA`, která přes resolver funguje; zjištěno zkouškou 25 s, ne měřením) |
| dns2tcp | dns2tcpc, stažení přes tunel (TXT/KEY) |
| exfil-slow | 1 dotaz za 5 až 10 s, 600 s, značka 52 znaků base32, typ A |
| exfil-short | krátké značky (12 znaků base32), typ A, 4 dotazy/s |
| exfil-multi | značka 52 znaků, TXT, střídání šesti domén `x1.test` až `x6.test`, 6 dotazů/s |
| doh | curl `--doh-url`, nové spojení na dotaz (původní, cíle web a web2) |
| doh-keep | jeden curl s `--rate`, trvalé spojení na DoH, náhodná jména `*.www.lab.test` |
| control | původní (A, TXT, HTTP) |
| control-names | CDN se zahešovanými jmény (A + HTTPS typ), DKIM/SPF/DMARC TXT, PTR na 60 adres, SRV (služby AD), DNSBL obrácené IP |
| control-av | antivirová reputace: hash 40 + 8 hex znaků, typ A, 2 dotazy/s |
| control-avburst | totéž 10 dotazů/s (plný sken disku; očekávaný nejtěžší případ pro T2) |
| control-mdns | mDNS na 224.0.0.251:5353, instance Chromecast s 32znakovým UUID (PTR/SRV/TXT) |
| control-browse | HTTPS i HTTP na web a web2, obyčejné DNS, malé stránky |
| control-download | HTTPS stažení 4 MB opakovaně |
| control-stream | HTTPS stažení omezené rychlostí (dlouhé spojení) |
| control-poll | HTTPS dotaz na API každou 1 s, nové spojení |
| control-pollkeep | HTTPS dotazy na API 1/s v jednom trvalém spojení |

Sady: **ladicí** (seed 17001) každý režim jednou; **držená** (seed 17101) každý režim jednou a navíc druhá relace iodine, dnscat, doh a control (původní předregistrace „2x“). Seed určuje pořadí relací a parametry v předem daném rozsahu (velikost dat, přesné tempo). Relace 180 s, exfil-slow 600 s. Držená sada se pustí jednou po zmrazení kódu (commit zapsaný níže před během).

### Prahy (dodatek)

| práh | metrika | splněno, když |
|---|---|---|
| K17-T1 | iodine (všechny typy) | ≥ 80 % relací (beze změny) |
| K17-T1b | dnscat2 (všechny typy), dns2tcp, exfil-* | hlásí se po režimech s Wilsonovým intervalem; cíl ≥ 80 % souhrnně, bez nároku na každou variantu |
| K17-T2 | falešné poplachy `dns_tunnel_names`, `dns_zone_enumeration` a `doh_suspected` na všech kontrolách (laboratoř B i A) | 0 |
| K17-T3 | DoH (doh, doh-keep) | hlásí se s Wilsonovým intervalem; cíl ≥ 80 % |

Nezachycené varianty se zapíší do registru slepých míst (níže) s mechanismem, proč je pravidlo nevidí, ne do „ladění, dokud to nevyjde“. Žádné tvrzení o 100% detekci.

### Hrozby validity dodatku

Varianty i kontroly staví autor detektoru; kontroly napodobují tvar skutečného provozu (CDN, AV reputace, mDNS), ale nejsou to záznamy skutečných zařízení. Jedna relace na režim v ladicí sadě. Seznam známých DoH resolverů se v laboratoři neověří provozem. Okno detekce je délka relace (180 s nebo 600 s); v provozu s jinou délkou okna se mění hlavně T2 a pomalé tunely.

## Ladicí běhy a změny (zapsáno před drženými běhy)

### Laboratoř B, ladicí sada (seed 17001, `debugB5`, 26 relací)

Vady laboratoře a vyhodnocení nalezené při ladění (opraveny, nejde o ladění detektoru):

1. Převod konců řádků v PowerShellu jednou vyprázdnil `composeb.yml`, `tunnel_client.sh` a `k17_labb.py` (čtení relativní cestou selhalo a zapsal se prázdný řetězec); obnoveno z původního obsahu, první pokus o běh B5 se tím nespustil.
2. Vyhodnocení bez `SALTICUS_REPLAY_NOW`: motor bral skutečný čas, takže relace starší než okno motoru vypadly a měly nula nálezů (doh, doh-keep, dnscat-aaaa, exfil-multi vypadaly jako minuté). Nyní čas přehrávání = konec relace, stejně jako v laboratoři A.
3. Opakované vyhodnocení ve stejném pracovním prostoru: paměť nálezů z minulého běhu potlačila nové. Nyní má každá relace čistý pracovní prostor.
4. dns2tcp přes resolver unbound relaci nenaváže (klient jen opakuje „auth“, 346 dotazů za 150 s, žádná data); přímo na autoritu stáhne 5,4 MB za pár sekund. Relace se proto vede přímo na autoritu (jako iodine) a byla znovu zachycena (`debugB5x`). Původní relace se do výsledků nepočítá.
5. Vyhodnocení DoH počítalo zásah i za nález na špatný cíl; nyní se počítá jen nález na DoH server laboratoře (10.88.0.70) a nálezy na jiné cíle se hlásí zvlášť (`doh_misattributed_findings`).

Výsledek předregistrovaného detektoru (D1 beze změn prahů) po opravách vyhodnocení: iodine 5/5, dnscat2 5/5, exfil 1/3 (exfil-multi ano, exfil-slow a exfil-short ne), dns2tcp 0/1 (relace ještě přes resolver, bez dat), DoH 2/2, ale **každá DoH relace dala navíc dva nálezy na weby** (10.88.0.10 a 10.88.0.11), na které klient po DoH přistupoval: rys C2 byl pravdivý pro každý cíl hosta. Kontroly 0/10.

Změny detektoru na ladicí sadě (commit `08c4210`), každá s důvodem:

| změna | důvod (mechanismus) | dopad na ladicí sadě |
|---|---|---|
| T3 `tunnel_slow_*`: ≥ 30 různých jmen, podíl různých ≥ 0,9, délka ≥ 40, entropie ≥ 4,2, bez ohledu na typ a tempo | exfil-slow (1 dotaz za 5 až 10 s, typ A, base32) nesplní T1 (typ) ani T2 (objem). Hustá kódování (base32, base64) mají při délce ≥ 40 entropii nad 4,2, hex (hashe AV, dnscat2) nejvýš 4,0 | exfil-slow zachycen (78 jmen, entropie 4,58); control-av (hex, 3,75) a avburst zůstávají tiché |
| T4 `tunnel_card_*`: ≥ 1 000 různých jmen, podíl různých ≥ 0,9, podíl typů nesoucích data ≥ 0,5, entropie ≥ 3,0, délka ≥ 8 | dns2tcp (přímo na autoritu) posílá krátká jména (12 znaků) a data nese v TXT odpovědích; tvar jména T1 až T3 nesplní | dns2tcp zachycen (555 447 jmen za 150 s) |
| `tunnel_allow_zones`: reputační zóny (Sophos, McAfee GTI, ESET, Spamhaus včetně HBL, SURBL, URIBL, DNSWL, Mailspike, Team Cymru) | T3 by jinak zachytil i legitimní hashe v base32 (Spamhaus HBL kóduje SHA-256 v base32, 52 znaků). Útočník tyto zóny neovládá, takže seznam nevytváří cestu pro tunel | v laboratoři žádný (kontroly používají vlastní zóny) |
| DoH C2 zpřesněno: kandidát musí být „bootstrapovaný“ (bez SNI, nebo jeho SNI host přeložil obyčejným DNS) a další cíle hosta musí mít SNI, které obyčejným DNS nepřeložil | bez toho se jako DoH resolver označí i weby, na které klient po DoH přistupuje (chybné přiřazení cíle) | DoH 2/2 na správný cíl, 0 nálezů na weby |

Po změnách (binárka z `08c4210`): iodine 5/5, dnscat2 5/5, dns2tcp 1/1 (`debugB5x`), exfil 2/3, DoH 2/2 se správným cílem, kontroly 0/10, chybně přiřazené DoH nálezy 0. Nezachyceno: exfil-short (12 znaků base32, typ A, 4 dotazy/s, 625 jmen za 150 s). Dalším snižováním prahů by se dostal do pásma DNSBL a CDN kontrol (control-names: 304 jmen DNSBL, délka 12,8, entropie 2,97), proto se nemění a jde do registru slepých míst.

