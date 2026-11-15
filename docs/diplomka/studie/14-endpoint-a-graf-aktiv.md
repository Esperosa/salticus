# Studie 14A: endpoint telemetrie a graf aktiv (spojení, proces, důvěra, soukromí, objem)

Stav 2026-11-15. Podle protokolu `00-protokol.md` (v1.0). Podklady: `14-endpoint-a-graf-aktiv/extrakce.csv` (52 řádků, id `E14-xxx`), `hledani.csv`, `neovereno.md`. Doplňuje starší `08-endpoint-telemetrie.md`, který vznikl z veřejných stránek bez extrakční tabulky a **v závěrech se nepoužívá**. Druhá část kroku 14 (provozní telemetrie) je v `14-provozni-telemetrie.md`.

Pozor na tři odchylky od zadání. (1) CAPTAIN je článek z NDSS **2025**, ne 2022 (arXiv 2404.14720); článek NDSS 2022 s tímto názvem jsem nenašel. (2) Soubor `F:\bakula-soak\run-v2-72h\status.md` neexistuje, pro kontext měření jsem použil jen `docs/diplomka/eval/soak-findings.md` (soak v1). (3) Nezávislá kontrola podle §9 protokolu **nebyla provedena**, protokol ji vyžaduje jiným kontrolorem; tato studie proto nemá status „zkontrolováno“.

## 1. Abstrakt a hlavní závěry

- Spojení se na proces váže u všech čtených zdrojů stejně: lokální a vzdálená adresa a port, protokol, identifikátor procesu a čas. Sysmon ID 3 je ve výchozím stavu **vypnuto** a nese `ProcessGuid` (E14-001, E14-002); Defender XDR drží `InitiatingProcessUniqueId` = Process Start Key (E14-011); Tetragon, ETW provider Kernel-Network a osquery socket_events mají podobná pole (E14-032 až E14-034).
- Jediné nalezené **měření míry přiřazení** spojení k procesu (zeek-osquery, 11 Linux hostů, 3 dny): **96,05 % TCP**, **86,61 % všech toků**, **≈ 50 % UDP**, jednoznačný proces jen **88,53 %** (E14-046, E14-047). Je to horní odhad za příznivých podmínek, ne výchozí předpoklad.
- Join klíč Community ID je 5-tice bez směru zahashovaná SHA-1 (E14-012); o NAT mlčí (E14-012) a RFC 2663 uvádí, že NAPT překládá i porty, takže 5-tice před a za překladem se liší (E14-049). NAT-aware párování je naše práce, ne převzatá.
- Endpoint zdroje přiznávají ztráty: Falco považuje 1 až 2 % zahozených událostí za přijatelné (E14-035), osquery audit může při zaplnění backlogu ztrácet události (E14-033), Elastic Defend „není navržen pro úplný záznam“ (E14-036).
- Agent není pravda: v laboratorním testu komerčních EDR byla z **112 útoků více než polovina úspěšná** a většina bez alertu (E14-040); sensor blinding vyžaduje vysokou integritu (E14-041); tamper protection na Linuxu je jen audit (E14-039).
- Silent agent: veřejné výchozí prahy jsou **Wazuh 15 minut** pro Disconnected (E14-037) a **7 dní** pro Inactive u Defenderu (E14-038); Defender odlišuje „impaired communications“ od „no sensor data“ (spojení je, data jen částečná).
- Provenance IDS: na DARPA datech přesnost 0,98 až 1,0 (Unicorn, E14-016), na produkčních datech FPR pěti PIDS **0,0001 až 0,5065** (E14-024) a AUC klesne o 26,77 % při jiném hostu a o 38,03 % při jiné platformě (E14-025); jednoduchý allowlist procesů „matches or exceeds“ vybrané naučené modely (E14-026, jen abstrakt).
- Objem: kauzalitu zachovávající redukce ušetří 56 až 77 % audit logů (E14-042); Sysmon ID 7 plošně nezapínat (E14-004).
- Právo ČR (jen pro dokumentaci nasazení): § 316 odst. 2 a 3 zákoníku práce a čl. 5 a 35 GDPR (E14-044, E14-045).

## 2. Metodika a PRISMA

| krok | počet | poznámka |
|---|---:|---|
| záznamů v `hledani.csv` | 49 | 24 WebSearch dotazů, 25 načtení stránek (WebFetch); z toho dotazů „proti“ 2 |
| výsledků vyhledávání vrácených (součet sloupce) | 352 | součet pole `pocet_vysledku`; deduplikace záznam po záznamu nesledována (odhad autora: stovky unikátních) |
| prohlíženo (součet) | 53 | stránky skutečně otevřené |
| plný text nebo oficiální stránka zhodnocena | ≈ 45 | |
| zahrnuto do extrakce | 52 řádků z 34 zdrojů | |
| z toho V3 / V2 / V1 | 49 / 2 / 1 | V1 řádek (E14-028 ATLAS) není v závěrech |

Odchylky od protokolu (přiznané): protokol žádá minimálně 15 dotazů na RQ a aspoň 3 dotazy „proti“. Tady je 24 vyhledávacích dotazů na šest podtémat dohromady a dotazy „proti“ jsou 2 (kritika provenance IDS, selhání/tamper agentů); citační řetězení do plné hloubky u 5 klíčových prací nebylo dělané. Dotazy „proti“ pro soukromí a sampling jsem nevedl samostatně. PDF jsem uložil přes WebFetch a text vyčetl pomocí `pdftotext` (Unicorn, SIGL, HOLMES, Karantzas a Patsakis, CCS 2016); u HTML (CAPTAIN, průmyslové PIDS, zeek-osquery) čtení omezil nástroj na prvních 100 000 znaků. Hodnoty z WebFetch jsem u právních textů a u části dokumentace uvedl jako „parafráze WebFetch“, kde nebyla doslovná citace.

## 3. Výsledky podle podtémat

### 3.1 Jak nástroje skládají síťová a endpointová data

| nástroj | co jsem ověřil (V3) | co ne |
|---|---|---|
| Sysmon (ID 1, 3, 7, 11, 13, 22) | ID 1: `ProcessGUID` unikátní „across a domain“; ID 3 vypnuto výchozím stavem, vazba `ProcessId`+`ProcessGuid`; ID 7 jen s `-l` a „significant amount of logging“; ID 11 vznik souboru; ID 13 změna hodnoty registru; ID 22 DNS dotaz procesu bez ohledu na úspěch i cache; čas v UTC; filtry include/exclude na hostu (E14-001 až E14-008) | pole Zeek, výkonnostní měření |
| konfigurace SwiftOnSecurity | README: filtry „as little performance impact as possible“, AV je zdroj šumu, netrackuje autentizaci (E14-010) | samotné XML `sysmonconfig-export.xml` jsem nečetl, tedy pravidla pro ID 3, 7, 11, 13, 22 neznám |
| konfigurace olafhartong (sysmon-modular) | moduly po číslech ID, profily pro Sysmon 15.21, 14.16, 13.34, 12.03, výchozí schema 4.90; excludes-only profil „very verbose“; CI neměří objem (E14-009) | obsah modulů |
| Wazuh | životní cyklus agenta, Disconnected po výpadku keep-alive, výchozí 15 m (E14-037) | integrace Sysmon, rozhodovací pravidla (V1) |
| Velociraptor | artefakt Windows.ETW.KernelNetwork: provider Kernel-Network, události ConnectionAttempted/Accepted, filtry po adrese, portu a procesu, vyžaduje NT_USER/SYSTEM (E14-032) | artefakt Netstat |
| osquery | socket_events přes `bind()` a `connect()`, zapnout `--audit_allow_sockets`, vypnuto kvůli zátěži, ztráta při zaplnění backlogu (E14-033) | sloupce `process_open_sockets` (V1) |
| Fleet | nečteno | vše |
| Elastic Defend a detekční pravidla | sleduje TCP spojení, nikoli úplný záznam; doporučuje Packetbeat a Winlogbeat Sysmon (E14-036); pravidla v TOML pod Elastic License v2 (E14-050) | pole `process.entity_id` v síťových událostech |
| Defender XDR schéma | DeviceNetworkEvents: LocalIP/Port, RemoteIP/Port, Protocol, InitiatingProcessId, InitiatingProcessUniqueId (Process Start Key), InitiatingProcessCreationTime; `ReportId` jednoznačné jen s DeviceName a Timestamp (E14-011) | |
| Falco, Tetragon | Falco: drop counter, 1 až 2 % přijatelných drops (E14-035); Tetragon: TCP connect přes TracingPolicy s kprobe, výstup procesu a 5-tice (E14-034) | overhead Tetragonu stránka neuvádí |
| Zeek + endpoint | zeek-osquery: párování 5-ticí, 96,05 % TCP (E14-046); Community ID (E14-012) | Zeek+Sysmon konkrétní benchmark (nenalezeno) |
| Security Onion | Community ID zapnuto v Zeeku a Suricatě, dashboard podle hodnoty (E14-013) | Elastic Agent a Sysmon (V0) |
| Timesketch | import CSV/JSONL se třemi povinnými poli `message`, `datetime`, `timestamp_desc` (E14-051) | analyzátory (V1) |

#### Tvrzení výrobců (nepoužito v závěrech)

| výrobce | co veřejně tvrdí | úroveň |
|---|---|---|
| OpenEDR (Comodo) | process monitor, network monitor, file-system mini-filter, registry monitor, „Full Attack Vector Visibility including MITRE Framework“ (E14-052) | V3 jako popis, **ne** jako ověření schopnosti |
| CrowdStrike | pole NetworkConnectIP4 | V1, oficiální dokumentace nepřístupná |
| SentinelOne | události IP Connect jako samostatná tabulka, spojení s procesem přes join | V1, jen integrace třetích stran |
| Splunk, ExtraHop (NOC/SOC) | zkrácení MTTD až o 65 % | V1, tvrzení výrobce |

### 3.2 Provenance graf a process lineage (DARPA TC, OpTC, SIGL, Unicorn, ATLAS, Holmes, CAPTAIN)

Datasety:

| dataset | rozsah | licence a formát | řádek |
|---|---|---|---|
| DARPA TC Engagement 5 | květen 2019; TA1: cadets, clearscope, fivedirections, marple, theia, trace; velikost v README není | „public domain“, „as-is“, Avro (CDM), hostováno na Google Drive Five Directions | E14-029 |
| OpTC | ≈ 1 TB komprimovaného JSON, 500 hostů z 1 000, 2 týdny, formát eCAR, složka `ecar-bro` má FLOW-START anotované bro-id | „public domain“, „as-is“, Distribution A | E14-030 |
| ATLASv2 | 154 GB, 2 VM Windows 7, 4 dny benigní a 5. den útoky, Sysmon + Windows Security audit (ETW) + Carbon Black, labely EventRecordID | licence v textu neuvedena | E14-027 |

Systémy:

| systém | co jde převzít | metrika z čteného zdroje | omezení |
|---|---|---|---|
| Unicorn (NDSS 2020) | okolí R hopů v grafu snižuje FP; sketch grafu | StreamSpot: R=3 precision 0,98, recall 0,93 (R=1: FP 14/19/25/20/18 na 25 grafů, R=3: 0/0/2/0/0); DARPA CADETS/ClearScope/THEIA precision 0,98/0,98/1,0 (E14-014 až E14-016) | model se dynamicky neadaptuje, změna normálu vyvolá FP (E14-017) |
| SIGL (USENIX Sec. 2021) | graph LSTM autoencoder pro instalace | 625 škodlivých instalátorů: precision 0,94, recall 0,99; FPR 2,47 % (29 z 1 176 benigních grafů) (E14-018, E14-019) | doména instalátorů |
| HOLMES (S&P 2019) | mapování na TTP a prerekvizity | 3 M událostí za 5 dní → 86 kroků; 0 false alarmů na 2 týdnech benigní aktivity (E14-020, E14-021) | práh laděn na stejných datech |
| CAPTAIN (NDSS 2025) | adaptivní propagace tagů, gradient | 11,49x méně false alarmů než Morse (nevážený průměr 7 poměrů); E3 Trace: 22 500 → 1 099 (E14-022) | slabý baseline; zbytkové FP (E14-022) |
| ATLAS (USENIX Sec. 2021) | sekvenční model z kauzálního grafu | V1, v závěrech nepoužito (E14-028) | |

Kritika: průmyslové hodnocení pěti PIDS dává FPR 0,0001 až 0,5065 na produkčních sandboxech (E14-024), AUC pokles 26,77 % (jiný host) a 38,03 % (jiná platforma) (E14-025) a autoři tvrdí, že DARPA je jednohostový red-blue scénář (E14-031, V2). Samostatná práce s auditovaným E3 a časovým dělením zjistila, že allowlist názvů a cest procesů z tréninku „matches or exceeds“ naučené baseliny (E14-026, jen abstrakt).

**Rozpor a jeho vysvětlení.** DARPA výsledky (0,98 až 1,0) a produkční FPR (až 0,5065) jsou v rozporu jen zdánlivě: DARPA je jednohostové, krátké a čisté; produkční benigní aktivita se mění. Uvádím rozsah, nesčítám.

**Co jde převzít do Skákavky.** Z grafu to není detekční model (přenositelnost je nízká), ale (a) schéma uzlů a hran (proces, soubor, soket, DNS dotaz) z Sysmon ID 1, 3, 11, 13, 22, (b) pravidlo „kontext v okolí R≥3 snižuje FP“ jako hypotézu, (c) povinný baseline allowlist, (d) dataset OpTC s `ecar-bro` pro test párování, (e) formát výstupu pro Timesketch.

### 3.3 Svázání spojení s procesem, 5-tice, čas, NAT, více adres

- Spojení↔proces: Sysmon ID 3 (E14-001), Defender (E14-011), ETW Kernel-Network (E14-032), eBPF Tetragon (E14-034), osquery audit (E14-033). Pokrytí: TCP 96,05 %, UDP ≈ 50 % (E14-046); UDP chybí hlavně kvůli DNS (89 % UDP toků) a snímkování stavu soketů.
- Jednoznačnost: průměrně 1,17 kandidátního procesu na tok; opakované použití pid/fd kolem `execve` 0,18 % přiřazených toků; NAT virtuálních strojů chybně přiřazen hypervizoru 2,29 % (E14-047).
- 5-tice: Community ID je symetrická (menší IP:port první), SHA-1, base64, prefix `1:`; podporují ji Suricata 4.1+, Zeek 2.5+, osquery 4.2.0+, Security Onion 2.0+ (E14-012).
- NAT: překlad zachovává směr, ale mění adresy a porty (E14-049); Community ID NAT nepokrývá (E14-012); zeek-osquery uvádí NAT VM jako zdroj chyb (E14-047). **Nenalezeno** publikované měření NAT-aware korelace.
- Čas: Sysmon používá UTC (E14-003). NTP dosahuje na LAN stovek mikrosekund a po internetu desítek milisekund (RFC 5905 §1, řádek P14-011 ve studii 14B). Kerberos toleruje typicky 5 minut (P14-014), takže hodiny hostu mohou být dále než síťový sensor, aniž by si toho někdo všiml. Číselné **okno** pro párování zeek-osquery neuvádí (E14-048).
- Více adres hostu: zeek-osquery nachází chyby při IPv4/IPv6 (SIIT, Skype) a při opakovaném použití IP po VPN (E14-047); identita hostu přes IP byla 100% jednoznačná (E14-047), proces jen 88,53 %.

### 3.4 Důvěra v agenta, tampering, silent agent, nezávislé potvrzení

| signál | prahy z dokumentace | řádek |
|---|---|---|
| Wazuh: agent Disconnected | po výpadku keep-alive, výchozí `agents_disconnection_time` 15 m (v 4.x 10 m dle vyhledávače, V1) | E14-037 |
| Defender: Inactive | žádné signály více než 7 dní | E14-038 |
| Defender: Misconfigured | „Impaired communications“ (omezené spojení), „No sensor data“ (spojení je, data částečná) | E14-038 |
| Sysmon ID 4, 16, 255 | změna stavu služby, změna konfigurace, chyba při zátěži | E14-006 |
| Defender: `DeviceEvents` `ActionType == "TamperingAttempt"` | na Linuxu jen audit | E14-039 |
| Falco `scap.n_drops` | 1 až 2 % přijatelné | E14-035 |

Tampering: blinding kernel callbacků a EtwTi vyžaduje vysokou integritu, ze střední integrity nejde (E14-041); lab test ukázal, že z 112 útoků byla více než polovina úspěšná a většina bez alertu (E14-040). Sysmon sám uvádí, že se před útočníkem neskrývá (E14-006). Elastic doporučuje doplnit síťovou vrstvu (E14-036). Z toho plyne návrh (extrapolace, viz §6): agent je **tvrzení s důvěrou závislou na zdraví agenta**, a rozpor „endpoint říká nic, síť říká spojení“ je silnější signál než ticho agenta.

### 3.5 Soukromí a právo (jen shrnutí do dokumentace nasazení, bez právních závěrů)

- Zákoník práce § 316: odst. 2 bez „závažného důvodu spočívajícího ve zvláštní povaze činnosti zaměstnavatele“ nesmí zaměstnavatel narušovat soukromí monitorováním (včetně kontroly e-mailu); odst. 3 při existenci důvodu musí zaměstnance přímo informovat o rozsahu a způsobu kontroly (E14-044, znění k 2026-11-01).
- GDPR: čl. 5(1)(c) minimalizace, 5(1)(e) omezení uložení, čl. 35 posouzení vlivu, čl. 88 pravidla pro zaměstnance (E14-045).
- Neověřeno (V1): WP249, rozsudek Bărbulescu, stanoviska ÚOOÚ (viz `neovereno.md`).
- Do dokumentace nasazení: účel a právní základ zapsat, uvést rozsah sbíraných polí (např. příkazové řádky mohou obsahovat hesla), dobu uchování, kdo vidí data, informování zaměstnanců předem, pseudonymizace uživatele v exportech. Zda jde o „závažný důvod“, rozhodne právník, ne tato studie.

### 3.6 Objem dat: filtrování, agregace, sampling, retence

- Filtrování u zdroje: Sysmon include/exclude (E14-005), ID 7 opatrně (E14-004; u ID 10 stránka Sysmon rovněž varuje před velkým objemem, samostatný řádek v extrakci chybí), moduly sysmon-modular (E14-009); Falco `base_syscalls` (E14-035); osquery nezapínat sockety automaticky (E14-033).
- Agregace: CPR průměrně 56 %, CPR+PCAR 70 %, s doménovou znalostí 77 % redukce; Linux 5,26x a Windows 2,56x kapacity; 31 hostů (E14-042). HOLMES 3 M událostí → 86 kroků, ale to je redukce na úrovni výstupu detektoru, ne ukládání (E14-020).
- Sampling: Sci Rep 2023 na NetFlow 1:1000: OC-SVM accuracy 0,936 a 0,916, iForest ≈ 0,5; práce má vnitřní rozpor v FAR (E14-043); sampling je tedy použitelný jen s měřením.
- Retence: čl. 5(1)(e) GDPR (E14-045); konkrétní doby z literatury nejsou. Návrh tří vrstev je v §6 (extrapolace).
- Čísla o objemu Sysmon na hosta (V1) jsou rozptýlená o řád, proto je nepoužívám.

## 4. Syntéza

Kvantitativní souhrn podle §8 protokolu se nedá udělat: žádná metrika nemá ≥ 3 srovnatelné studie. Provenance IDS: FP rozsah 0 až 25 z 25 grafů (Unicorn, R=1 vs R=3), FPR 2,47 % (SIGL), FPR 0,0001 až 0,5065 (5 PIDS na produkci), 5 různých metrik a datasetů, žádný vážený průměr. Přiřazení spojení↔proces: jediná práce (11 hostů, 344 366 toků), tedy rozsah jedním bodem. Heterogenita je maximální.

## 5. Závěry

| Z-id | tvrzení | důkazy | jistota | důvody snížení | použitelnost | doporučená akce |
|---|---|---|---|---|---|---|
| Z14A-1 | Vazba spojení na proces existuje ve všech čtených zdrojích a opírá se o stabilní ID procesu (ProcessGuid, Process Start Key); Sysmon ID 3 je výchozím stavem vypnuto. | E14-001, E14-002, E14-011, E14-032, E14-034 | vysoká | pouze dokumentace | ano | pole `proc_id` a `proc_start` v modelu spojení; kontrola, že ID 3 je zapnuto |
| Z14A-2 | Reálné přiřazení toku procesu: TCP 96,05 %, všechny toky 86,61 %, UDP ≈ 50 %, jednoznačný proces 88,53 %. | E14-046, E14-047 | střední | jedna práce, 11 hostů, Linux, 3 dny, VPN | s úpravou | přiřazení vést s nejistotou, nikoli booleanem; UDP/DNS neočekávat |
| Z14A-3 | 5-tice Community ID je vhodný join klíč, ale neřeší NAT, VLAN ani MPLS; NAPT mění porty. | E14-012, E14-049 | vysoká (tvrzení o spec), střední (důsledek pro naše prostředí) | nepřímost | s úpravou | vlastní NAT-aware tabulka mapování, test na soaku |
| Z14A-4 | Endpoint zdroje ztrácejí události (Falco 1 až 2 % přijatelné, osquery audit backlog, Elastic nekompletní). | E14-033, E14-035, E14-036 | vysoká | pouze dokumentace | ano | chybějící událost endpointu = „nevím“, ne „nebylo“ |
| Z14A-5 | Agentovi nelze slepě věřit: > 50 % z 112 laboratorních útoků uspělo a většina bez alertu; blinding vyžaduje vysokou integritu. | E14-040, E14-041, E14-039 | střední | preprint, lab, vendor mix, E3/E4 | ano | nezávislé potvrzení ze sítě pro uzavření nálezu |
| Z14A-6 | Veřejné prahy zdraví agenta: Wazuh Disconnected 15 m, Defender Inactive 7 dní, rozlišení „impaired“ a „no sensor data“. | E14-037, E14-038 | vysoká | pouze dokumentace; Wazuh 4.x starší 10 m z V1 | ano | vlastní práh s násobkem intervalu hlášení, ne 7 dní |
| Z14A-7 | Provenance IDS výsledky se mezi DARPA a produkcí liší o řády a modely se špatně přenášejí; allowlist je silný baseline. | E14-016, E14-024, E14-025, E14-026 | nízká až střední | preprinty, jednodatasetové, abstrakt | s úpravou | převzít jen schéma a baseline; detektor nepřebírat |
| Z14A-8 | Redukce objemu zachovávající kauzalitu: 56 až 77 %. | E14-042 | střední | 2016, jedna laboratoř, 31 hostů | s úpravou | agregační pravidla Sysmon; nejdřív změřit na vlastních datech |
| Z14A-9 | Sampling zhoršuje detekci a výsledky jsou citlivé na model (iForest ≈ náhoda). | E14-043 | nízká | vnitřní rozpor, 1 míra vzorkování | s úpravou | sampling jen s měřením, ne plošně |
| Z14A-10 | Datasety OpTC a DARPA TC E5 jsou „public domain“; OpTC nese bro-id u endpoint toků. | E14-029, E14-030 | vysoká | nic neověřuje kvalitu labelů | ano | OpTC `ecar-bro` použít k validaci párování |
| Z14A-11 | § 316 ZP a GDPR čl. 5, 35 ukládají závažný důvod, informování, minimalizaci a posouzení vlivu. | E14-044, E14-045 | vysoká (znění), nelze o výkladu | právní výklad mimo rozsah | ano (dokumentace) | šablona oddílu „soukromí“ v dokumentaci nasazení |

## 6. Překlad do praxe

Označení: **[důkaz]** = přímo z řádku; **[extrapolace]** = odhad autora, postup uveden.

1. Model události: `ConnObs{host_id, ts_utc, proto, local ip:port, remote ip:port, proc_id, proc_start, source}` [důkaz: E14-001, E14-011]. Zdroj označit (`sysmon3`, `etw`, `osquery`, `ebpf`), protože jejich pokrytí je různé [důkaz: E14-033, E14-036].
2. Párování toku sítě s ConnObs: klíč Community ID nebo 5-tice bez směru [důkaz: E14-012]; hostitel přes množinu adres (IPv4, IPv6, DHCP historie) [důkaz: E14-047]; pro NAT dodatečná tabulka překladů nebo shoda na vzdálené straně a čase [extrapolace: z RFC 2663, E14-049].
3. Časové okno: **žádné z literatury** [E14-048]. Navrhuji `okno = max(rozlišení toku sensoru, |offset hostu| + jitter)` s odhadem offsetu hostu z párovaných událostí [extrapolace: NTP na LAN stovky µs, ale Kerberos toleruje až minuty, viz P14-011 a P14-014]. Nastavit z naměření na soaku, ne ručně.
4. Výsledek přiřazení je pravděpodobnost, ne fakt: kandidátů 1,17 na tok (E14-047), UDP ≈ 50 %. Nejasné → kandidáti s vahami, plánovač ověřování tuto nejistotu zdědí.
5. Zdraví agenta: `agent_health ∈ {ok, gap, impaired, dead}` ze tří signálů: poslední heartbeat, ID 4/16/255 Sysmonu, drops (Falco `scap.n_drops`, osquery) [důkaz: E14-006, E14-035, E14-037, E14-038]. Prahy: heartbeat gap = 3 × hlásicí interval [extrapolace; veřejná čísla 15 m a 7 dní jsou pro naše použití hrubá].
6. Nezávislé potvrzení: pokud síť vidí tok z hostu s `agent_health = ok` a endpoint hlásí „žádné spojení“, je to konflikt a zvyšuje podezření na tampering nebo chybu agenta [extrapolace, důvod E14-040, E14-041]. Naopak ticho agenta s aktivním tokem ze sítě je silný signál „agent nehlásí, host žije“.
7. Graf aktiv: uzly `Host`, `Process`, `File`, `RegKey`, `Socket`, `DnsName`; hrany podle Sysmon ID 1, 3, 11, 13, 22 [důkaz: E14-002, E14-007, E14-008]; nepřebírat PIDS detektory [Z14A-7]; zavést allowlist baseline [E14-026].
8. Objem: Sysmon ID 7 a 10 vypnuto bez filtru, 3, 22 jen se zdrojovým filtrem, ostatní podle sysmon-modular [E14-004, E14-009]; agregace opakovaných spojení stejnou dvojicí proces/cíl v okně [extrapolace z CPR, E14-042]. Cílovou redukci nesliboval; změřit.
9. Retence (tři vrstvy) [extrapolace, opora čl. 5(1)(e) GDPR E14-045]: surové události krátce (dny), agregáty a nálezy déle, pseudonymizace uživatelských jmen v exportech. Konkrétní doby určí dokumentace nasazení.
10. Dokumentace nasazení, oddíl soukromí: § 316 ZP (E14-044), GDPR (E14-045), seznam polí, doba uchování, informování zaměstnanců, kontakt na právníka.

## 7. Hypotézy k empirickému ověření (soak harness)

Kontext našich čísel (`soak-findings.md`, soak v1): `c2_beacon` detekováno 4,7 % se správným typem 0,3 %, `rogue_device` 0,2 %, falešné rozdělení identity 8,7 % při změnách adres (DHCP, swap), exfiltrace 0 % ze zdrojového pořadí. Literatura k těmto číslům nic přímého neříká; nejblíže je přiřazení spojení k procesu (E14-046) a jednoznačnost hosta (E14-047).

| H | změna | očekávaný efekt (rozsah z důkazů) | metrika | scénář a seedy | kritérium zamítnutí |
|---|---|---|---|---|---|
| H14A-1 | simulovat endpoint události (proces→spojení) a párovat s toky 5-ticí a oknem | TCP 96 % [E14-046]; UDP ≈ 50 % | podíl přiřazených TCP/UDP, podíl jednoznačných | 10 seedů × 3 konfigurace sítě; ladění na 5 seedech, test na držených 5 | TCP < 85 % nebo jednoznačnost < 80 % |
| H14A-2 | NAT-aware tabulka | bez NAT-aware přiřazení za NAT ≈ 0 [extrapolace]; s tabulkou ≥ 90 % | stejné, jen toky za NAT | variantní generátor NAT | s tabulkou < 80 % TCP za NAT |
| H14A-3 | host_id z endpointu místo IP | falešné rozdělení identity z 8,7 % (soak v1) pod 2 % [extrapolace: host 100 % jednoznačný v E14-047] | podíl falešných rozdělení a sloučení | scénáře DHCP churn a swap | > 4 % nebo zvýšení falešných sloučení nad 1,7 % |
| H14A-4 | `agent_health` s prahem 3 × interval; síť jako nezávislý signál | TPR detekce „agent ticho, host žije“ ≥ 0,95 při FPR ≤ 2 % [extrapolace, v literatuře nic] | TPR, FPR, čas do detekce | simulace vypnutého a blindovaného agenta | TPR < 0,9 nebo FPR > 5 % |
| H14A-5 | allowlist (cesty procesů z tréninku) jako povinný baseline | dorovná naučené modely [E14-026] | FPR při stejném TPR, časově oddělený test | držené scénáře, časový split | allowlist prohrává o > 10 p.b. proti našemu postupu na držených datech |
| H14A-6 | endpoint proces u c2_beacon | typová správnost 0,3 % (soak v1) výrazně vzroste; velikost efektu **není v literatuře** | podíl správného typu, latence | rodina `c2_beacon` | zlepšení < 10 p.b. |
| H14A-7 | agregace opakovaných událostí | 56 až 77 % redukce [E14-042] bez poklesu recallu nálezů | objem, recall nálezů | všechny rodiny | recall klesne o více než 2 p.b. |

## 8. Hrozby validity

- Dokumentace výrobců není měření (Sysmon, Wazuh, Defender, Elastic, Falco, osquery): popisuje záměr produktu.
- Jediné měření párování (zeek-osquery) má 11 Linux hostů, 3 dny, provoz přes VPN, prototyp v Pythonu.
- DARPA a OpTC mají kvalitu labelů závislou na autorech; průmyslové hodnocení je preprint bez recenze (E14-024, E14-025).
- Číselné hodnoty z WebFetch u dlouhých HTML a právních stránek jsou čtené z prvních 100 000 znaků a z odpovědi malého modelu; u řádků označených „parafráze WebFetch“ nejde o doslovnou citaci. Kontrola druhým člověkem nebyla.
- Sci Rep 2023 má rozpor mezi tabulkou a závěrem (FAR); hodnoty používám jen z tabulek.
- Dataset ATLASv2 předpokládá benigní prvních 4 dny (E14-027).
- Prahy zdraví agenta jsou výchozí hodnoty produktů, ne optimální.

## 9. Co NEBYLO nalezeno

- Číselné časové okno nebo tolerance při párování spojení a procesu (zeek-osquery ho neuvádí).
- Měření NAT-aware korelace síť↔endpoint.
- Benchmark Zeek + Sysmon join (jen zeek-osquery, jiný endpoint zdroj).
- Akademické měření četnosti silent failure EDR; jen blogy výrobců (V1).
- Mimicry útoky na provenance IDS (dotaz nic nevrátil).
- Obsah konfigurace SwiftOnSecurity a sysmon-modular pro ID 3, 7, 11, 13, 22 (XML nečteno).
- Oficiální Fleet, Wazuh+Sysmon a Elastic `process.entity_id` stránky (404 nebo nenačteno).
- Plné texty WP249, rozsudku Bărbulescu a stanoviska ÚOOÚ.
- Výchozí chování a velikost objemu Sysmon na hostu z recenzované práce.
- Nezávislá kontrola podle §9 protokolu.
