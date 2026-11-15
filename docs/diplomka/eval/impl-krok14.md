# Krok 14: endpointová telemetrie jako plnohodnotný zdroj, graf aktiv a incidentů; část C2 provozní telemetrie (předregistrace a stav)

Datum zahájení 2026-11-15. Výchozí stav: konec kroku 13 (commit `32b438a`), engine `v3`, preset `recommended()` beze změny, vše nové za přepínačem, výchozí vypnuto. Zadání: `F:\claude-tmp\briefs\krok14-endpoint.txt` a doplnění o část C2. Rešerše: `docs/diplomka/studie/14-endpoint-a-graf-aktiv.md` a `14-provozni-telemetrie.md` (vznikají souběžně; do kódu se z nich přebírá jen ověřené, V3/V2).

## Výchozí stav (z kroku 13, držené seedy, kandidát `final`)

Detekce 86,9 %, FP poměr 1,058, omylem zavřené 0 z 5475, správná třída poruch 5,0 %, správné `catalog_id` 0,7 %, A5 (kategorie složky mixu) 54,0 %, rozdělení společné příčiny v incidentech 83,9 %. Příčina slabin tříd a katalogu: engine skoro nepřijímá provozní telemetrii (jediný provozní důkaz jsou vzory z toků E1 až E3), simulované poruchy ji nenesou. Stejný typ příčiny jako dřív u TLS a DNS: chybějící vstup.

## Předregistrace (zamčeno commitem před prvním řádkem kódu kroku 14)

### Společná pravidla měření

Platí protokol z kroku 13 (matice 10 seedů x 3 konfigurace sítě, párově podle `run_seed` a `network_id`, bootstrap po sítích stratifikovaný seed x konfigurace, B = 2000, Wilson doplňkově, ladicí a držené seedy zvlášť, poměr součtů).

- Ladicí seedy (smí se ladit): 20261102, 20261103, 20266101 až 20266108.
- **Nové držené seedy kroku 14 (zapsáno dopředu, použít jednou na konci, nikdy nepoužity):** 20267101, 20267102, 20267201, 20267202, 20267301, 20267302, 20267401, 20267402, 20267501, 20267502. Seedy držené z kroku 13 (20265xxx) se znovu nepoužijí jako držené (byly vyhodnoceny), smí se jen jako kontrola regrese (označí se tak).
- hn_* ladicí (hn_cdn_update_download, hn_mail_newsletter_burst, hn_admin_bulk_ssh, hn_authorized_internal_scan) a držené (hn_nightly_cloud_backup_upload, hn_db_replication_bulk, hn_monitoring_snmp_sweep, hn_password_sync_periodic) zvlášť.
- Běhy: Idle, maska 0x3FFFFC, až 16 vláken celkem (zadání koordinátora přepisuje strop 6 vláken ze zadání kroku 14), PID dlouhého běhu se nedotýkám.
- Rozsah: 8 sítí na seed v matici (jako krok 13), XXXL a XXL zvlášť jako stres.
- Změna kódu po prvním měřicím běhu na ladicích seedech se zapíše jako odchylka s důvodem; na držených seedech se po měření nic nemění.
- Circularita simulace (přiznáno předem): simulátor provozní i endpointové telemetrie vzniká z našich popisů typů; přesnost klasifikace na simulaci je proto horní odhad za předpokladu, že popis signálů je správný. Proti tomu stojí tři zátěžová ramena (výpadek telemetrie, zavádějící signály, typ mimo katalog), reálná data pro endpoint (EVTX, OTRF) a nezávislost zdrojů signálů (tabulka signálů je z primárních zdrojů rešerše, ne z kódu detektoru). Tvrzení „funguje na reálné síti“ z těchto čísel neplyne.

### Část A: endpoint jako plnohodnotný zdroj, graf aktiv a incidentů

Ramena: `off` (stav kroku 13), `on100`, `on60`, `on30` (pokrytí agenty), `silent` (agent mlčí), `lying` (kompromitovaný agent lže ve prospěch útočníka), `on100+ops` (kombinace s částí C2). Párově proti `off`.

| práh | definice | splněno, když |
|---|---|---|
| A1 | případy „síť nestačí“ (rodiny: exfil_cloud_storage_upload, bucket_mass_download, clicks_to_rare_destination, cloud_api_discovery_burst, drive_by_bulk_download, c2_cloud_storage_dead_drop, dns_zone_enum_burst, c2_dns_txt_beacon; zvlášť hlášeno po rodinách): správné rozhodnutí (zobrazen nález útoku) `on100` − `off` | ≥ +10 p. b. a dolní mez 95 % intervalu > 0 |
| A2 | detekce bezpečnostních útoků celkem, `on100` − `off` | ≥ +2 p. b., dolní mez > 0 |
| A3 | zobrazené FP na síť-den, `on100` / `off` | ≤ 1,10 |
| A4 | omylem zavřené útoky (počet útoků s omylem zavřeným nálezem), všechna ramena včetně `lying` | `on100` ≤ `off`; `lying` ≤ `off` + 0,5 % útoků; horní mez Wilson se hlásí |
| A5 | pozitivní důkaz neškodnosti (podepsaný proces se známým hashem a očekávaným chováním): hn_* zobrazeno, `on100` − `off` | ≤ −10 p. b. (méně zobrazených neškodných) bez zvýšení omylem zavřených |
| A6 | podíl případů rozhodnutých autonomně (zavření pozitivním důkazem nebo potvrzení) se zaručenou mezí chyby | hlásí se podíl a horní mez Wilson 95 % chyby ≤ 1 % |
| A7 | čistota seskupení incidentů s grafem aktiv (A3 kroku 13 definice) a úplnost | čistota ≥ 90 % na oknech mixů, úplnost (pár nálezů téže události ve stejném incidentu) ≥ 70 %, nálezů na incident ≥ 2; roztříštění se hlásí |
| A8 | čas k rozhodnutí (medián virtuálních sekund od prvního důkazu po rozhodnutí) | `on100` ≤ `off` |
| A9 | objem uložených endpointových dat na host a den po filtrování | ≤ 5 MiB, hlásí se medián a p95 |
| A10 | pokrytí agentů 0/30/60/100 %: monotónnost detekce a odhad pokrytí | `on100` ≥ `on60` ≥ `on30` ≥ `off` − 0,5 p. b. |
| A11 | `silent`: detekce − `off`; nesoulad síť vs. agent (host komunikuje, agent mlčí) hlášen jako slepé místo | detekce ≥ −1 p. b.; ≥ 90 % mlčících hostů s provozem označeno |
| A12 | `lying`: detekce − `off` | ≥ −1 p. b. a žádný chráněný nález zavřen endpointem |
| A13 | parsery (Sysmon, Wazuh, osquery, auditd, Falco, EVTX): fuzz, 100 000 náhodných a poškozených vstupů na formát | 0 paniků, limity drženy |
| A14 | reálná data: EVTX-ATTACK-SAMPLES a OTRF produkční cestou (evtx → adaptér → graf → nálezy) | ≥ 95 % záznamů s podporovaným ID událostí rozparsováno bez chyby; hlásí se, kolik technik vyústí v zobrazený nález; rozdíl proti simulaci se popíše kvalitativně |
| A15 | determinismus a regrese: stejný seed dvakrát bit po bitu, `soak verify`, `legacy` a `v3` bez nových přepínačů bajtově beze změny, golden snapshot a no_memory zelené | shoda |
| A16 | paniky a porušené invarianty ve všech ramenech | 0 |

### Část C2: provozní telemetrie

Ramena: `off` (stav kroku 13), `ops` (nové příjmy a klasifikace za přepínačem `ops_telemetry`), `ops-drop30`, `ops-drop60` (výpadek telemetrie 30 a 60 % zdrojů), `ops-noise` (zavádějící a šumové signály, včetně signálů, které poruchu jen napodobují), `ops-unknown` (porucha typu mimo katalog). Párově proti `off`.

| práh | definice | splněno, když |
|---|---|---|
| C1 | správná klasifikace poruch (třída `porucha`) u nálezů z poruch, `ops` | ≥ 85 % na ladicích i držených seedech; hlásí se po typech a celkem s intervalem |
| C2 | správné `catalog_id` tam, kde telemetrie existuje (typ má v katalogu signál a ten byl doručen) | ≥ 80 %; po typech |
| C3 | kde telemetrie chybí (`ops-drop*`, hostitel bez zdroje): explicitní hlášení „nelze určit, chybí telemetrie X“ | ≥ 90 % nálezů bez doručeného signálu nese hlášení a žádné zařazení do třídy; chybné jisté zařazení ≤ 10 % |
| C4 | útok maskovaný jako porucha zařazený jako porucha (mixy útok+porucha, útok se signály poruchy v okně) | ≤ 5 %; měřeno zvlášť |
| C5 | porucha maskovaná jako útok zařazená jako útok | ≤ 10 %; měřeno zvlášť |
| C6 | porucha nikdy nezavřená jen proto, že není útok: poruchy zavřené automaticky z důvodu „není útok“ | 0 (porucha jde do fronty provoz a zůstává viditelná) |
| C7 | A5 kroku 13 (správná kategorie složky mixu, držené) | ≥ 85 % (v kroku 13: 54,0 %) |
| C8 | čistota seskupení incidentů se společnou příčinou (A3 a A4 kroku 13) | čistota ≥ 90 %, rozdělení společné příčiny ≤ 30 % (v kroku 13: 83,9 %), úplnost zapsána; roztříštění se hlásí |
| C9 | omylem zavřené útoky a FP: `ops` proti `off` | omylem zavřené 0 (horní mez Wilson), FP poměr ≤ 1,10, detekce ≥ −0,5 p. b. |
| C10 | `ops-unknown` (typ mimo katalog) | ≥ 90 % označeno „nelze určit“, ne jistě zařazeno jinam; nesmí se zavřít |
| C11 | `ops-noise` | C1 ≥ 75 % a C4 ≤ 5 % |
| C12 | parsery provozní telemetrie (SNMP, syslog RFC 5424 a 3164, DHCP lease logy, ARP/ND, NTP, health-check, certifikát, záloha a replikace, Prometheus/Zabbix/Nagios) | fuzz 100 000 vstupů, 0 paniků, limity drženy |
| C13 | determinismus a regrese jako A15 | shoda |

### Co se předem přiznává jako riziko

(1) C1 a C2 mají horní odhad dané uzavřeným světem simulace. (2) Cíl A1 závisí na tom, že simulace endpointu věrně dává signál tam, kde síť nestačí; reálná data jsou jen EVTX a OTRF bez síťové složky. (3) Část C2 může zhoršit FP, pokud se provozní signál stane záminkou k přesunu útoku do fronty provoz; proto C4, C6 a C9. (4) Prahy se nesnižují po pohledu na data; nesplněný práh se zapíše poctivě.

### Rozhodnutí o výchozím zapnutí

Přepínač se navrhne do `recommended()` jen tehdy, když na držených seedech projdou prahy A2 až A4, A12, A16 (část A), resp. C1, C2, C6, C9, C13 (část C2) a LOFO neukáže prvek se zápornou hodnotou. Jinak zůstává volitelný. Dlouhý běh kroku 8 (endpoint on, 60 %) se porovná s předchozím megaběhem a zahrne do rozhodnutí.

## Tabulka stavu (průběžně)

| bod | stav |
|---|---|
| 1 rešerše (studie 14 a 14-provozni-telemetrie) | probíhá (rešeršní agent) |
| 2 předregistrace | **hotovo (tento commit)** |
| 3 implementace A: adaptéry, svázání s procesem, graf, pokrytí, pozitivní důkaz | nezačato |
| 3 implementace C2: model, adaptéry, simulátor, klasifikace, katalog | nezačato |
| 4 reálná data (EVTX, OTRF) | nezačato |
| 5 měření ladicí | nezačato |
| 5 měření držené | nezačato |
| 6 souhrn a doporučení `recommended()` | nezačato |

## Implementace (průběžně zapisováno)

### C2: provozní telemetrie

| blok | soubory | co |
|---|---|---|
| model a sklad | `src/ops_telemetry/mod.rs` | `OpsSignal` (čas, klíč, hodnota, rozsah IP/CIDR/`*`), `OpsStore` (strop 50 000 signálů, stáří 24 h, budoucnost 1 h, klíč `[a-z0-9_]{1,48}`, konečná hodnota, rozsah ≤ 16), evidence pokrytí zdrojů (`heartbeat`, `silent_sources`: zdroj bez signálu a heartbeatu 3 h je tichý) |
| adaptéry | `src/ops_telemetry/adapters.rs` | syslog (RFC 5424 i BSD), SNMP text (`snmpwalk`), Prometheus text, Nagios, DHCP (dhcpd, Kea), chrony, ARP; tabulka vzorů jako podřetězce; řádek ≤ 8 KiB; fuzz 30 000 vstupů x 6 formátů bez paniky |
| katalog | `data/incident-catalog.json` v1.1.0, `tools/k14_catalog_signals.py` | pole `ops_signals` (klíč, váha 1 až 3) u všech 75 typů, 101 klíčů |
| diagnóza | `ops_telemetry::diagnose` | skóre typu = přítomný důkaz / (přítomný + 0,5 x chybějící důkaz váhy >= 2 u ŽIVÉHO zdroje), váha klíče x idf přes katalog; typ se přijme se skóre >= 0,45 a odstupem od druhého >= 0,10, jinak třída bez typu (`nejednoznacne`), slabá shoda = `neurceno`; **jen typy nálezů z množiny COMPATIBLE** (dostupnost, objem, nový partner) se přeřazují, útokové typy (signatury, skeny, hádání hesel, tunely) zůstávají `utok` a nesou jen poznámku `explains_partly` |
| bez telemetrie | `diagnose` | tokový vzor poruchy (E1 až E3) a žádný signál a aspoň jeden tichý zdroj -> `neurceno` s textem „nelze určit, chybí telemetrie: ...“; bez tokového vzoru zůstává `utok` |
| simulátor | `src/soak/ops_sim.rs` | `--ops-telemetry on`, `--ops-drop`, `--ops-noise`, `--ops-unknown`; signály podle `ops_signals` typu s pravděpodobností váhy (0,9 / 0,6 / 0,35 za cyklus), pokrytí zdrojů v síti (SNMP 90 %, syslog 85, DHCP 80, DNS 70, ARP, NTP, probe 60 %), podsíťové signály s rozsahem /24, hostové jen na hostu, šum, zavádějící signály u útoků (`noise` > 1), typ mimo katalog (`sys_unclassified_error`) |
| engine | `V3Features::ops_telemetry` | mimo `recommended()`; v soaku zařazení nálezu jde do `attacks[].catalog` a počet doručených signálů do `ops_signals` |
| vyhodnocení | `tools/k14_ops.py` | C1 až C5, C10 po typech a celkem s Wilsonem |

Pravidla ověřená testy: úplná sada signálů každého typu ho pozná nebo vyjde `nejednoznacne` (sdílené signály OPS-027 a CHG-006, OPS-045 a OPS-020, OPS-033 a OPS-034), nikdy jistě jiná třída; útokové typy se nepřeřazují; chybějící telemetrie se hlásí; rozsah IP a CIDR se dodržuje.

### A: endpoint

| blok | soubory | co |
|---|---|---|
| hash binárky | `endpoint/model.rs`, `sysmon.rs`, `osquery.rs` | `Process::hash` (SHA-256 ze Sysmon `Hashes` a osquery `sha256`) |
| kontext procesu u nálezu | `endpoint/graph.rs` | `bind_process` (spojení -> proces přes obraz a čas, okno 300 s), redakce příkazové řádky (`redact_cmdline`: klíč=hodnota, příznaky s hodnotou, base64 >= 40 znaků, `-EncodedCommand`), pseudonymizace uživatele solenou funkcí (`Privacy`) |
| seznam povolených | `endpoint/graph.rs` `Allowlist` | hash + podpis + výrobce + protistrana (CIDR, `*` se nepřijímá) + vlastník + expirace (bez expirace se nepřijímá); `EndpointSignal::Allowed`, `LrTable::endpoint_allow` 0,05, u chráněných nálezů jen `Undetermined` |
| graf aktiv | `endpoint/graph.rs` `Graph` | uzly host, uživatel, proces, protistrana, soubor; hrany Spawned, Connected, LoggedOn, Wrote, MovedTo, Ran; kauzální řetěz, první výskyt, export DOT, meze 5 000 uzlů a 20 000 hran |
| pokrytí agentů | `endpoint/graph.rs` `agent_mismatch` | host s provozem v síti: `blind` (agent nikdy nehlásil) a `silent` (umlkl), příznak že ostatní agenti žijí |
| rozšířené indikátory | `endpoint/correlate.rs` (`Policy::extended`) | kancelářský proces spouští skript, cloudový synchronizační nástroj, DNS průzkum (`axfr`, `ls -d`), smyčka TXT dotazů, nahrání skriptem, průzkum cloudovým CLI (>= 3 různé příkazy), stažení a spuštění |
| přepínač | `V3Features::endpoint_ext` | mimo `recommended()`, vyžaduje `endpoint` a `protect` |
| simulace | `soak/endpoint_sim.rs` | události pro varianty, kde síť nestačí (rclone, PowerShell, nslookup, aws CLI, stažení a spuštění), pro `clicks_to_rare_destination` záměrně shodné s běžným kliknutím z pošty (koncový nástroj to neodliší) a podepsané nástroje hn_* s hashem (20 % instancí s vlastním nepodepsaným nástrojem); `--endpoint-allow` (70 %) |

### Deník odchylek a oprav na ladicích seedech

1. Smoke 20261102 (4 sítě, ops): C1 71 %, C2 34 %, C4 22 %, C5 24 %. Příčina: signály poruch měly rozsah /24 pro všechny klíče, takže se přenášely mezi souběžnými poruchami a na útoky v téže podsíti. Oprava v simulátoru (realismus): /24 jen u podsíťových klíčů, ostatní na postiženém hostu; do rozsahu se počítá i `attacker_device` (hn_authorized_internal_scan neměl žádné signály).
2. Množina `COMPATIBLE` rozšířena o typy, které nález skutečně produkuje u poruch a změn (egress_volume_anomaly, ingest_volume_anomaly, novel_peer_burst, novel_burst_peer, peer_burst, tls_novel_burst, retry_storm, vpn_reconnect_storm).
