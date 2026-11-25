# Audit pokrytí soak harnessu a eval kódu

Stav k 4. 11. 2026. Čistě čtecí audit: nic nebylo spuštěno ani změněno, čísla jsou z existujících `final-report.json` a ze zdrojového kódu (`src/soak/traffic.rs`, `src/soak/benign_regular.rs`, `src/eval/behavior_anchor.rs`, `docs/diplomka/dataset-registry.md`, `docs/diplomka/eval/anchor-split.txt`). Obsahový filtr nezasáhl. ATT&CK je použit jen jako seznam kategorií pro kontrolu pokrytí.

## 0. Co se dá a nedá ověřit

- Ověřeno: počty instancí (pole `families.*.truth`, `lookalikes.*.occurrences`) z `F:\bakula-soak\run80h`, `run-v2b` a `ab\k4\blind\*`; váhy, délky a intenzity z `plan_episode`.
- Neověřeno: `run-v3-72h` a `run-v2-72h` nemají `final-report.json` (jen `.out/.err`), nezapočteny. Ladicí běhy `ab/s1..s4`, `l-*`, `r3-*` (seedy 20261102-04) jsem neagregoval.
- Počty ve slepých bězích jsou po světech, ne po ramenech: `legacy`, `s2` a `s4` běží nad stejnými seedy, stejně `n10`/`n50` (jen jiný násobek šumu). Instance se proto nesčítají, nezávislých světů je 80 (x1) + 6 (xxxl), ne 80+32+32+6. Jde o počty z reportu `s4`.
- Datasetové údaje (licence, velikost) u kandidátů v sekci 6 jsou z paměti, nestahoval jsem a neměl jsem ověření z webu. Před použitím ověřit.
- Identity churn / změna IP zařízení: v `soak/*` jsem nenašel generátor (DHCP je jen konstrukce sítě, `dhcp: bool`). Může existovat v `identity_lab.rs`, to jsem nečetl.

## 1. Rodiny útoků (19): počet instancí

Zdroj: `final-report.json`. Sloupec D/H = zda je rodina v ladění (T) nebo držená (H, `Family::held_out`). Poznámka: i držené rodiny viděly kroky 1 a 2, "slepé" jsou jen držené seedy a zamčená část kotvy (komentář v `traffic.rs`).

| Rodina | D/H | run80h (seed ...0131, ladicí svět) | run-v2b (seed ...1101) | slepý x1 (80 sítí, 2 seedy) | slepý xxxl (6 sítí) | Váha výběru |
|---|---|---:|---:|---:|---:|---:|
| port_scan_vertical | T | 6122 | 6336 | 178 | 8 | 12 |
| port_scan_horizontal | T | 4018 | 4092 | 121 | 5 | 8 |
| ssh_bruteforce | T | 7114 | 7198 | 231 | 14 | 14 |
| c2_beacon | T | 3992 | 4213 | 106 | 4 | 8 |
| ddos_volume | T | 2070 | 2003 | 57 | 3 | 4 |
| exfiltration | T | 2566 | 2636 | 70 | 5 | 5 |
| lateral_movement | T | 3581 | 3622 | 93 | 3 | 7 |
| rogue_device | T | 1503 | 1581 | 43 | 3 | 3 |
| exploit_attempt | T | 5061 | 5145 | 124 | 12 | 10 |
| dns_tunnel | T | 2125 | 2047 | 55 | 2 | 4 |
| credential_stuffing | T | 0 | 3569 | 100 | 8 | 8 |
| slow_scan | H | 3117 | 3076 | 98 | 6 | 6 |
| ransomware | H | 0 | 1400 | 29 | 2 | 3 |
| cryptomining | H | 0 | 2012 | 73 | 4 | 4 |
| insider_hoarding | H | 0 | 1375 | 29 | 4 | 3 |
| web_exploit | H | 0 | 3173 | 87 | 2 | 7 |
| ics_attack | H | 0 | 183 | 3 | 0 | 3 (x5 jen Industrial) |
| fleet_beacon | H | 0 | 987 | 34 | 2 | 2 |
| apt_chain | H | 0 | 1553 | 42 | 5 | 3 |
| Součet | | 41 269 | 56 201 | 1 573 | 92 | |

Pozn.: run80h i run-v2b jsou 15 664 resp. 2 312 sítí (1,49 mil. resp. ~1 mil. cyklů). Slepý x1 pochází ze 2 seedů × 40 sítí. Ve `slepém` je držených rodin 395 z 1573 (25 %), z toho ics_attack jen 3 instance (jeden pár světů), takže závěry o ICS jsou statisticky nepoužitelné (CI v `gates.txt`: 100 % -> 33 %, n=3). run80h je starší svět se 11 rodinami (8 držených rodin tam chybí).

Pozorování k rodinám:
- Rodiny jsou nerovnoměrné: ssh_bruteforce 231 vs. ics_attack 3 (poměr 77:1). Slepý test dává u rodin s n < 50 (apt_chain 42, fleet_beacon 34, ransomware 29, insider 29, rogue_device 43, ics 3) široké intervaly (kontrafaktuální detekce apt 90,5 % -> 100 %, CI +2,1 až +18,8).
- Soak je od `Family::ALL` zrcadlově svázán s váhami v poli `weights` (pozice podle indexu enumu), křehké při přidání rodiny.

## 2. Parametrické variace, které už existují

- Intenzita: 3 pásma (0,8-1,0 s 40 %; 0,4-0,7 s 40 %; 0,15-0,35 s 20 %). Intenzita škáluje počty toků (`intensity * 400/1500/8000 ...`), objem exfil (`3e9 * intenzita` bajtů), interval ssh/ slow (60 s * (1 + (1-i)*10)). Skrytost = jen tato osa plus `ids_visible` (podíl 0,1-0,8 podle rodiny).
- Délka: rozsah cyklů po rodinách (scan 1-3, ssh 2-12, c2 6-40, mining 12-200, fleet 24-400, apt 96-720; cyklus = 30 min); u c2/slow_scan/rogue/dns_tunnel 25 % šance na 6× delší kampaň.
- Tempo je v kódu pevné po rodinách, kromě slow_scan / ssh. Skrytost proti IDS: jen binární `ids_visible`.
- Senzor: degradace telemetrie (`drop_p`, `dup_p`, `skew_s`, `outage_p`, `ids_coverage`, slepé podsítě). Šum 1×/10×/50× (`--noise`).
- Archetypy sítí: 10 (Soho, Smb, Datacenter, IotHeavy, Campus, Enterprise, Metro, Industrial, Hospital, Cloud); 18 rolí, 24 typů služeb. V run-v2b: Soho 507, Smb 427, Enterprise 344, Datacenter 200, IotHeavy 189, Campus 174, Cloud 157, Industrial 121, Hospital 116, Metro 76.

## 3. Provozní události a lookalike (14) + 12 pravidelných vzorů

| Lookalike / událost | Ops? | run80h | run-v2b | slepý x1 | xxxl |
|---|---|---:|---:|---:|---:|
| backup_burst | ne | 9954 | 9470 | 265 | 15 |
| authorized_scanner | ne | 9921 | 8412 | 252 | 5 |
| flash_crowd | ne | 9898 | 9521 | 279 | 11 |
| software_update | ne | 10129 | 9621 | 315 | 14 |
| ntp_fanout | ne | 10049 | 8333 | 269 | 14 |
| service_crash | ano | 0 | 7315 | 215 | 6 |
| retry_storm (výpadek linky) | ano | 0 | 4240 | 114 | 7 |
| batch_job | ano | 0 | 4138 | 107 | 2 |
| collector_replay | ano | 0 | 3135 | 95 | 5 |
| sensor_crash | ano | 0 | 3087 | 75 | 1 |
| patch_window | ano | 0 | 3076 | 91 | 3 |
| device_onboarding | ano | 0 | 2840 | 87 | 0 |
| log_corruption | ano | 0 | 2067 | 55 | 2 |
| device_decommission | ano | 0 | 2022 | 63 | 1 |

Slabá místa: v xxxl 0-2 instance u 5 druhů; ve slepém x1 u decommission 63, sensor_crash 75. Žádný lookalike není "držený": všech 14 se ladí a testuje na stejné množině (neexistuje obdoba `held_out()` pro benigní). Ladicí `run80h` ops události vůbec nemá (0 z 9).

Dvanáct pravidelných benigních vzorů (`RegularKind`): MonitoringPoll, MonitoringAgent, NtpSync, DnsRecursion, UpdateCheck, VpnKeepalive, BastionAdmin, RemoteSupport, CiCd, CdnStreaming, ScheduledBackup, ScriptPolling. Škálují se šumem 1×/10×/50×. Parametry jsou z dokumentace protokolů (test hlídá cirkularitu).

## 4. Složené scénáře

Co je:
- `apt_chain` = jedna rodina s pevnými fázemi podle `progress`: <12 % skenování, <25 % exploit, <85 % pohyb, pak exfiltrace. 1553 (v2b), 42 (slepý). Pořadí a podíly fází jsou konstantní, nelze měnit.
- Šum + útok: po naplánování útoků dostane každý útok se 12 % pravděpodobností benigní událost ve stejném cyklu (výběr z 6: Backup, FlashCrowd, SoftwareUpdate, BatchJob, ServiceCrash, RetryStorm). Odhad ≈ 0,12 × 56 201 ≈ 6 700 případů v v2b (odhad, v reportu nezjišťováno zvlášť; skutečná shoda je i náhodná, protože počátky jsou rovnoměrné).
- Překryv útoků navzájem vzniká jen náhodou (Poisson, nezávislé počátky); není plánován ani měřen.

Co chybí:
- Dvě různé rodiny jedné kampaně na stejném cíli (scan -> brute -> lateral -> exfil jako samostatné rodiny se sdíleným útočníkem/oběťmi), kromě pevného `apt_chain`.
- Útok souběžný se senzorovou poruchou (sensor_crash, collector_replay, log_corruption nejsou v seznamu 12 % kombinací) a s onboardingem/decommission.
- Opakovaný útočník (stejný zdroj ve více dnech, recidiva po zablokování).
- Více útoků ve stejném okně na různé oběti (souběh dvou kampaní).

## 5. Datasety eval (CTU-13, IoT-23) a rozdělení kotvy

Kotva `anchor-split.txt`: 21 scénářů, 11 dev + 10 test (zamčeno, hash seznamu 15b0127a...).

| Dataset | Dev | Test | Rodiny/technika |
|---|---:|---:|---|
| CTU-13 | 6 (42,44,46,47,49,52) | 7 (43,45,48,50,51,53,54) | Neris ×3, Rbot ×4, Virut, Donbot, Sogou, Qvod, 2× neoznačeno; ~2,64 mil. toků, ~27 000 škodlivých |
| IoT-23 | 5 (4-1 honeypot, 3-1, 20-1, 34-1, 42-1) | 5 (5-1 honeypot, 7-1 Somfy, 8-1, 21-1, 44-1) | C&C, C&C-Torii, DDoS, FileDownload, PartOfAHorizontalPortScan, Attack; 3 benigní honeypoty |

Pozn.:
- Komentáře u `ANCHOR_DEV` v `behavior_anchor.rs` ("46 = Virut", "47 = Menti", "49 = Murlo") odporují registru (46 = neoznačeno fast-flux, 47 = Donbot, 49 = Qvod, Virut = scénář 54). Dokumentační nesoulad k opravě, ne chyba měření.
- Dataset pokrývá z 19 rodin v zásadě: C2/botnet (c2_beacon, fleet_beacon), horizontální scan, DDoS. Nic z: exfiltrace, lateral, brute-force (jen v IoT-23 jako "Attack"), ransomware, exploit, ICS, insider, tunelování, rogue device. Reálná data tedy ověřují jen cca 4 z 19 rodin a žádné provozní události.
- Dva scénáře jsou téměř bez škodlivých toků (Botnet-48: 63, Botnet-50: 50 z ~114-229 tis.), takže jsou k měření recallu skoro bezcenné. Botnet-45: 469. Test část má tedy efektivně méně škodlivých toků, než naznačuje počet scénářů.
- Mirai (43-1) je vynechán (9,36 GB).

## 6. Pokrytí z pohledu síťové obrany (ATT&CK kategorie a provozní poruchy)

### 6a. ATT&CK taktiky (14 enterprise) -> rodiny

| Taktika | Pokryto rodinami | Pozn. |
|---|---|---|
| Reconnaissance | port_scan_vertical/horizontal, slow_scan | dobře; chybí pasivní/OSINT (nepozorovatelné v síti) |
| Resource Development | -- | mimo dosah sítě, nevyžaduje se |
| Initial Access | exploit_attempt, web_exploit, credential_stuffing, ssh_bruteforce, rogue_device | chybí phishing/doručení (e-mail, stahování) |
| Execution | -- | hostová, mimo síť (jen nepřímo) |
| Persistence | -- | hostová |
| Privilege Escalation | -- | hostová |
| Defense Evasion | slow_scan, nízká intenzita, maskovaný rogue, dns_tunnel | jen pomalost; chybí obfuskace/šifrování v obvyklých protokolech, rozložení na více zdrojů |
| Credential Access | ssh_bruteforce, credential_stuffing | chybí password spraying (pomalé, rozložené), podvržení v lokální síti |
| Discovery | skeny | chybí vnitřní enumerace (SMB/AD/SNMP/ARP sweep) jako samostatná rodina |
| Lateral Movement | lateral_movement, apt_chain, ransomware (SMB) | jen jeden vzor hran 445/3389/22/135; chybí WinRM/jiné služby |
| Collection | insider_hoarding | OK |
| Command and Control | c2_beacon, fleet_beacon, dns_tunnel, cryptomining | chybí DGA/fast-flux, P2P, jitter/šifrovaný maskovaný HTTPS, nestandardní port |
| Exfiltration | exfiltration, insider_hoarding, dns_tunnel | chybí pomalá exfiltrace na legitimní cloudové služby |
| Impact | ddos_volume, ransomware, cryptomining, ics_attack | chybí amplifikační/odražená (příchozí) DoS, útok na dostupnost přes protokol |

Celkem: 9 z 14 taktik má aspoň jednu rodinu, 4 jsou mimo síťový dosah (Resource Dev, Execution, Persistence, PrivEsc). Ze síťově pozorovatelných taktik je největší díra Defense Evasion a Discovery.

### 6b. Třídy provozních poruch

| Třída | Pokryto | Instancí (v2b) |
|---|---|---:|
| Výpadek linky/ISP | retry_storm | 4240 |
| Pád/restart služby | service_crash | 7315 |
| Aktualizace/patchování | software_update, patch_window, UpdateCheck | 9621 / 3076 |
| Zálohy | backup_burst, ScheduledBackup | 9470 |
| Přetížení (bez útoku) | flash_crowd | 9521 |
| NTP | ntp_fanout, NtpSync | 8333 |
| Dávkové úlohy | batch_job | 4138 |
| Mizející/přibývající zařízení | decommission, onboarding | 2022 / 2840 |
| Porucha sběru/senzoru/logů | sensor_crash, collector_replay, log_corruption | 3087 / 3135 / 2067 |
| DNS výpadek / pomalá odpověď | NE (jen DnsRecursion jako benigní provoz) | 0 |
| DHCP (vyčerpání, pád, renew, změna IP zařízení) | NE (identity churn neověřen) | 0 |
| Vypršelý certifikát / selhání TLS | NE | 0 |
| Flapping (opakované kolísání linky/služby) | NE (retry_storm je jednorázový, 1-4 cykly) | 0 |
| Špatná konfigurace (duplicitní IP, špatná VLAN, smyčka, broadcast storm) | NE | 0 |
| Selhaná záloha / zaseklá úloha | NE (záloha je vždy úspěšná) | 0 |
| Výpadek napájení segmentu + hromadný restart | NE (patch_window je přibližně) | 0 |
| Selhání VPN / reconnect bouře | NE | 0 |
| Změna cloudu/migrace (nové externí cíle) | NE | 0 |
| Skenery správy a monitoring | authorized_scanner, MonitoringPoll | 8412 |
| Nasazení nového zařízení s novým chováním | částečně (onboarding) | 2840 |

## 7. Díry seřazené podle hodnoty pro produkční nástroj

Hodnota = jak často se to v reálu vyskytuje x jak drahá je chyba (falešný poplach nebo přehlédnutí).

1. Chybějící benigní třídy: DNS výpadek, DHCP/změna IP zařízení, vypršelý certifikát, flapping, špatná konfigurace. V produkci vyvolávají nejvíc falešných poplachů; v soaku je 0. Měřené FP (17,6 na sit-den) tak neodráží tuto třídu.
2. Souběh útoku s poruchou (ne jen 12 % se 6 lookalike): chybí sensor_crash, collector_replay, log_corruption, onboarding, decommission jako souběžná událost; chybí měření podílu odhalení při souběhu (recall v okně poruchy).
3. Nízký počet držených instancí u ics_attack (3 ve slepém x1, 0 v xxxl), apt_chain, fleet_beacon, ransomware, insider (29-42). Intervaly spolehlivosti jsou široké; ics_attack je statisticky nepoužitelný.
4. Žádné držené lookalike: všech 14 se ladí i testuje na stejné množině (riziko přeučení FP prahů na tvar generátoru).
5. Kampaně z více rodin: jen pevný `apt_chain`; chybí řetězení samostatných rodin se sdíleným útočníkem a variací pořadí/tempa.
6. Variace skrytosti: pouze 3 pásma intenzity + binární `ids_visible`; chybí rozložení útoku na více zdrojů/dní (distribuovaný, pomalý password spraying), nízké tempo u ostatních rodin (c2 jitter, exfil v malých dávkách).
7. Reálná data pokrývají jen botnet/C2, horizontální scan, DDoS; všech ostatních ~15 rodin ověřuje jen vlastní generátor (riziko cirkularity, i když je u pravidelných vzorů hlídáno).
8. Reálné datasety s benigním provozem: 3 honeypoty IoT-23 + CTU-13 pozadí je z 2011; chybí moderní benigní (cloud, QUIC, šifrované).
9. Nepokryté síťově pozorovatelné kategorie ATT&CK: vnitřní enumerace (Discovery), rozložené Credential Access, Defense Evasion nad pomalostí, DGA/P2P C2, odražený DoS.
10. Drobnosti: nesoulad komentářů u `ANCHOR_DEV` s registrem; váhy rodin vázané na pořadí enumu; Botnet-48/50 s pár desítkami škodlivých toků.

## 8. Návrh zvýšení pokrytí bez nových technik útoku

A. Parametrické variace existujících rodin (nový generátor nevznikne, jen se rozšíří osy v `plan_episode`):
- Intenzita: místo 3 pásem spojité rozdělení + nízké okraje (0,05-0,15) pro "těsně pod prahem".
- Tempo: násobič intervalu pro každou rodinu (0,25× až 8×), jitter u c2_beacon (0-50 %).
- Skrytost: více zdrojů (útok rozdělit na 1/3/10 IP), `ids_visible` nezávislé na rodině jako parametr.
- Délka: u rodin s max < 10 cyklů přidat dlouhý ocas (1 z 5 trvá 6×, jako už mají c2/slow).
- Každý parametr jako samostatná osa v reportu (tabulka rodina x pásmo), aby šlo číst citlivost.

B. Kombinace stávajících rodin do kampaní:
- Nový parametr kampaně = seznam (rodina, offset, délka) se sdíleným útočníkem a obětmi; stačí složit existující emitory (scan -> ssh_bruteforce -> lateral -> exfil; web_exploit -> c2 -> ransomware). Varianty pořadí i prodlevy.
- Rozšířit 12% souběh útok+lookalike na všech 14 a na dvojice (útok + 2 lookalike); cíl ≥ 30 instancí na každou dvojici rodina x lookalike v držených seedech.
- Plánované překrytí dvou útoků na různé oběti (měřit zvlášť).

C. Více provozních poruch a neškodných lookalike (kombinace/varianty existujících emitorů toků, ne nové útoky):
- DNS výpadek (klienti opakují dotazy, timeouty na 53), DHCP renew/změna IP zařízení (stejné MAC, nové IP), vypršelý certifikát (flow k službě selhávají a opakují se), flapping (retry_storm opakovaný 3-10× po 1-2 cyklech), selhaná/zaseklá záloha (opakované pokusy), výpadek napájení segmentu s hromadným restartem, VPN reconnect bouře, migrace do cloudu (nové externí cíle), špatná konfigurace (duplicitní IP, broadcast).
- Zavést `held_out` i pro lookalike (např. 4 z 14 + nové vyhradit pro slepý test).

D. Držené instance: zvýšit seedy slepého běhu pro rodiny s n < 50 (apt, fleet, ransomware, insider, rogue, ics), např. přes váhy `--families held-out` jen ve slepých bězích; plán jen jako čtecí návrh, žádné spuštění zde.

E. Další veřejné označené datasety (údaje z paměti, neověřeno, před použitím ověřit; nic nestaženo):

| Dataset | Obsah | Licence (orientačně) | Velikost (orientačně) | Co doplní |
|---|---|---|---|---|
| CIC-IDS2017 | 5 dní, brute force, DoS, web útoky, infiltrace, botnet, portscan; benigní provoz | volné pro výzkum s citací (UNB CIC) | PCAP ~50 GB, CSV toků ~0,5-1 GB (zip) | brute force, web exploit, portscan, DoS s moderním benigním provozem |
| CSE-CIC-IDS2018 | podobné, ve větší síti na AWS | AWS Open Data, citace | surové ~220+ GB, CSV několik GB | lateral/infiltrace, DDoS v měřítku |
| UNSW-NB15 | 9 kategorií útoků, 2,54 mil. záznamů | pro akademické použití, komerční jen se svolením UNSW | PCAP ~100 GB, CSV ~0,6 GB | exploit, fuzzers, backdoor, shellcode; syntetický |
| CICIoT2023 | 33 útoků v 7 třídách, 105 IoT zařízení | UNB CIC, výzkum s citací | desítky GB PCAP, CSV několik GB | IoT útoky (DDoS, recon, brute, spoofing, web, Mirai) |
| MAWI (+MAWILab) | trasy z páteřní linky WIDE, MAWILab přidává štítky anomálií | otevřená data, podmínky v archivu | trasy 15 min ~ stovky MB až GB, denní | benigní drift, dlouhodobá diverzita (málo štítků) |
| Bot-IoT, TON_IoT (kandidáti) | IoT/IIoT útoky + telemetrie, TON_IoT zahrnuje ICS | výzkumné, citace | desítky GB | ICS/IoT útok, nejbližší k `ics_attack` |
| UGR'16 (kandidát) | reálné flow ISP s injektovanými útoky | CC (podmínky ověřit) | desítky GB | benigní dlouhý ISP provoz pro FP |

Doporučení pořadí: (1) CIC-IDS2017 (nejmenší CSV, pokrývá brute force/web/portscan/DDoS, které IoT-23/CTU-13 nemají), (2) UNSW-NB15 jako nezávislá generalizace, (3) CICIoT2023 pro IoT, (4) MAWI pro benigní drift. Registr už je plánuje jako Vlnu 1 (zbytek); nový `ScenarioSource` nutný pro každý. Pozn.: kotvu rozdělit po dnech/souborech předem a zamknout, jako se dělá u CTU-13/IoT-23 (hash seznamu).

Provozní poruchy (DNS/DHCP/certifikáty/flapping) veřejné označené datasety s pozemní pravdou prakticky nemají; jedinou cestou je generátor (bod C), eventuálně Vlna 3 z registru (Mininet/Containerlab) s DHCP/NAT churnem.
