# Krok 17: vlastní Docker laboratoř se skutečnými záznamy provozních poruch, DNS tunelu a DoH

Datum zahájení 2026-11-18. Výchozí stav: konec kroku 16 (commit `8ddcf45`). Zadání: `F:\claude-tmp\briefs\krok17-lab.txt`. Rozsah: `docs/diplomka/rozsah-autonomie.md`.

Proč: v kroku 15 (P3) se ukázalo, že projev poruchy v simulátoru a v katalogu vznikly nezávisle, takže klasifikaci poruch (C1 až C5) na simulaci ověřit nejde (krok 15: C1 67 %, C2 47 %, C4 a C5 22 %). Veřejné datasety DoH a DNS tunelu vyžadují formulář s osobními údaji, proto se nepoužijí. Řešení: vlastní laboratoř na tomto počítači, kde je štítek (typ poruchy, začátek, konec) dán skriptem, který poruchu vyvolal.

## Předregistrace (zapsáno před kódem laboratoře a měření)

### Laboratoř A: provozní poruchy

Docker Compose `labs/k17/` na tomto počítači, sítě typu `internal` (bez cesty ven, domácí síť se nedotýká): `lan` 10.77.1.0/24 (klienti c1 až c4, monitorovací host, DHCP server dnsmasq, směrovač), `srv` 10.77.2.0/24 (resolver unbound, autoritativní nsd, NTP chrony, webová aplikace nginx + aplikace pod supervisord s HTTPS, rsyslog, sběrač). Směrovač je kontejner s IP forwardingem, klienti mají výchozí trasu přes něj. Telemetrie (vše skutečné výstupy nástrojů, žádný text psaný autorem do logu): syslog přes busybox `syslogd -R` do rsyslog (RFC 5424, odesílatel jako IP), SNMP (`snmpd` ve směrovači a v aplikaci, sběrač `snmpget` s převodem čítačů na rychlosti a využití, jak to dělá Zabbix nebo Cacti), DHCP logy dnsmasq a klientů `udhcpc`, arpwatch na směrovači, `chronyd -Q` (měření offsetu NTP), health-check ve formátu Nagios (stav se hlásí při změně, HARD po 3 pokusech) a blackbox styl Prometheus. Zachytávání: `tcpdump` v síťovém jmenném prostoru směrovače na rozhraní `lan` (obdoba SPAN na přístupovém uplinku); zpracování `zeek -C -r`. Surové záznamy jen v `F:\Projekty\bakula-datasets\lab-k17\`, v repu skripty, konfigurace a statistiky.

Scénáře (slot 450 s: 150 s normální provoz, 150 s porucha nebo útok, 150 s normální provoz po obnově; okna přehrávání 150 s zarovnaná na fáze). Očekávané `catalog_id` dané mechanismem poruchy, zapsané předem (v závorce přijatelné alternativy se stejným mechanismem):

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

Relace po 600 s: ladicí sada iodine 1x, dnscat2 1x, DoH 1x, kontrola 1x; držená sada iodine 2x, dnscat2 2x, DoH 2x, kontrola 2x.

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
