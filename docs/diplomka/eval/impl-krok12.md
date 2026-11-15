# Implementace, krok 12: chybějící vstupy, politika zavírání, pokrytí senzorů

Datum 2026-11-14. Navazuje na krok 11. Studie: `../studie/12-telemetrie-a-zavirani.md`. **Tato předregistrace vznikla před jakýmkoli kódem kroku 12** (v repu k tomuto commitu není žádná změna `src/`).

## 0) Stav práce (aktualizuje se; navázání po přerušení)

| část | stav |
|---|---|
| A studie | hotová; pole Zeek, Suricata, JA3, JA4 a RITA ověřena proti primárním stránkám (studie, oddíl 7); SOC zavírání je moje syntéza, citace chybí |
| D politika zavírání | `strict_close` implementován a otestován (commit `feat(context_gate)`); **ověření na datech běží** (rameno `sA`, seedy 20263101 a 20263102) |
| B vstupy | `src/l7.rs` (parsery Zeek ssl/x509/dns/http a EVE tls/dns/http, fuzz test), `behavior/l7.rs` (`tls_rare_transfer`, `tls_novel_burst`, `dns_zone_enumeration`), přepínače `l7_tls`, `l7_dns`, inbound toky a L7 v `BehaviorInput`, načítání z `zeek_dir` a EVE; endpointová telemetrie z kroku 8 je přepínač `endpoint`, beze změny |
| C simulace | svět `--l7 on` (`soak/l7sim.rs`): TLS a DNS metadata ke tokům po degradaci. **Nehotové:** kalibrace na veřejných datech, datasety, reálné přehrání, příčina LUFlow 1/259 |
| E pokrytí senzorů | nezačato |
| F žebřík s ECE, incident_id | nezačato |
| měření na držených seedech, soak verify, celý test | nezačato |

Důvod: rozsah (nové datové typy napříč parserem, modelem, behaviorální vrstvou, žebříkem a simulátorem, plus stahování a zpracování datasetů) přesahuje jeden průchod; raději stav přiznávám, než abych odevzdal polovinu jako hotovou.

## 1) Prahy (předregistrované, hodnoty se po měření nemění)

| id | práh | splněno, když |
|---|---|---|
| K12-1 | omylem zavřené útoky na všech sadách | 0 pozorováno; uvést horní mez Wilson 95 % (≈ 3,7/N). 0 pozorováno neznamená 0 zaručeno |
| K12-2 | detekce rodin s pozorovatelným útokem (`visible_flows` > 0) | ≥ 90 % u každé rodiny a dolní mez Wilson ≥ 85 % tam, kde n ≥ 50 |
| K12-3 | zobrazené FP na síť-den proti k8ref | poměr ≤ 1,15 |
| K12-4 | neškodné hn_* z **držené** poloviny | podíl zobrazených nejvýš o 10 p. b. nad základem k8ref |
| K12-5 | paniky, porušené invarianty, chráněná zavření | 0 |
| K12-6 | determinismus | `soak verify` zelený s novými přepínači |
| K12-7 | parsery TLS/DNS/HTTP | fuzz test (náhodné a poškozené vstupy), 0 paniků |
| K12-8 | zákaz paměti | `no_memory` zelený |
| K12-9 | LOFO a leave-one-tactic-out nových detektorů | detekce na rodinách mimo ladicí množinu ≥ 85 %, bez zhoršení základu o víc než 3 p. b. |
| K12-10 | žebřík L0 až L4: nejisté případy rozhodnuté správně, ECE, čas | změřit a hlásit; cíl správně ≥ 80 % rozhodnutých, ECE ≤ 0,10 |
| K12-11 | pokrytí senzorů | každý host a segment bez telemetrie v okně je v hlášení; slepý útok nevyvolá tichý nález |

## 2) Pravidla měření

- **Rozdělení hn_* na ladicí a držené.** Ladicí: hn_cdn_update_download, hn_mail_newsletter_burst, hn_admin_bulk_ssh, hn_authorized_internal_scan. Držené (nesmí se použít k ladění, jen jednou na konci): hn_nightly_cloud_backup_upload, hn_db_replication_bulk, hn_monitoring_snmp_sweep, hn_password_sync_periodic. Nové hn_* scénáře se přidávají s realistickými TLS a DNS poli a stejným rozdělením.
- Seedy: ladicí 20262301 až 20262302 a 20261102 až 20261104 (již viděné, jen ladění). **Nové držené seedy nikým neviděné: 20264101, 20264102, 20264201, 20264202, 20264301, 20264302**, pustí se jednou na konci. Seedy 20263101 až 20263302 jsou po kroku 11 spotřebované a nepoužijí se jako držené.
- Základ k8ref a poslední preset; kandidát = nové přepínače, výchozí vypnuto.
- LOFO: nové detektory se ladí bez rodin z množiny LOFO kroku 10 a bez taktik credential-access, discovery, lateral-movement; vyhodnocení po rodinách a taktikách.
- Provoz: Idle priorita, nejvýš 6 vláken, jedno rameno najednou; PID 118652 se nedotýká.

## 3) Návrh oprav (před kódem)

1. **Zavírání** (`context_gate.rs`, `closure_audit.rs`): kontext zavře nález jen pokud (a) záznam má vlastníka a expiraci, (b) **všechny** zdroje i cíle nálezu leží v rozsahu záznamu, (c) nález má identifikovaný zdroj. Jinak zůstane zobrazen s poznámkou. Audit log každého zavření, vzorek pro člověka. Regresní test: souběh skeneru a útoku z jiného zdroje se nezavře.
2. **Vstupy**: nové pole `TlsMeta`, `DnsMeta`, `HttpMeta` v `ConnectionObservation` (nebo souběžná tabulka), adaptéry Zeek `ssl/x509/dns/http` a Suricata EVE `tls/dns/http/fileinfo/anomaly`, fuzz test. Přepínače `tls_meta`, `dns_meta`, `http_meta`, `inbound`.
3. **Detektory** (každé aspoň dva nezávislé rysy, žádný port): šifrované stažení = rarita SNI v síti × poměr směrů × nový JA3 nebo čerstvý certifikát; zone enum = AXFR/IXFR nebo vysoký počet unikátních jmen s NXDOMAIN od vnějšího zdroje; shluk toků na nový cíl = rarita SNI + shluk + chybějící předchozí DNS.
4. **Pokrytí senzorů**: stav pokrytí po segmentech a hostech (poslední viděný tok, očekávaná aktivita), viditelný nález „bez telemetrie“, doporučení umístění tapu a zapnutých logů.
5. **Žebřík**: nové kontroly (TLS, DNS, endpoint) jako nezávislé druhy důkazu; `incident_id` v generátoru poruch a metriky seskupení.

## 4) Poznámky a odchylky

(zapisuje se průběžně)

## 5) Fáze „chytřejší korelace a práce s nejistotou“ (předregistrace, před kódem této fáze)

Studie: `../studie/12b-korelace-a-nejistota.md`. Přepínače: `hypotheses`, `evidence_lr`, `ladder_chain`, `retro`, `reopen`, `conformal`, `case_file`, `forensic_requests`; všechny výchozí vypnuto.

Metriky a prahy (hodnoty se po měření nemění):

| id | metrika | práh |
|---|---|---|
| K12-12 | správné rozhodnutí u případů, které žebřík dnes nechává nerozhodnuté (kontrafaktuální pravda) | ≥ 80 % z rozhodnutých; podíl rozhodnutých se hlásí zvlášť |
| K12-13 | ECE posteriorů žebříku (10 košů) a spolehlivostní diagram | ECE ≤ 0,10; Brier a log-loss vedle |
| K12-14 | autonomní zavření neškodného případu: omylem zavřený útok | 0 pozorováno, horní mez Wilson 95 % uvést; cíl horní meze ≤ 0,5 % při N ≥ 600 autonomních zavření, jinak „záruka nedosažena, rozhoduje člověk“ |
| K12-15 | omylem eskalovaný neškodný případ z autonomních rozhodnutí | horní mez Wilson 95 % ≤ 5 % |
| K12-16 | podíl autonomních rozhodnutí a podíl předaných člověku podle důvodu | hlásit; bez prahu (měření hranice automatizace) |
| K12-17 | konformální pokrytí na držených seedech | empirické pokrytí ≥ nominální 90 % − 2 p. b. |
| K12-18 | čas k rozhodnutí (cykly) a počet kontrol na případ | hlásit medián a p90; cíl: bez nárůstu mediánu o víc než 20 % proti stavu bez fáze |
| K12-19 | čistota seskupení do incidentů (podíl nálezů incidentu patřících jedné pravdě) a nálezů na incident; čas k prvnímu nálezu | čistota ≥ 90 %; ostatní hlásit |
| K12-20 | správné oddělení útoku od poruchy (kontrafaktuál, jen případy s oběma typy ve stejném okně) | ≥ 85 % |
| K12-21 | audit: každé autonomní rozhodnutí a každé přehodnocení má záznam s důkazy | 100 % |
| K12-22 | forenzní žádost bez schválení nikdy neprovedena | 0 provedení |

Provedení: A/B proti rameni bez fáze (stejné seedy, svět k10 s `--l7 on`), ladění na ladicích seedech a ladicích hn_*, držené seedy 20264101 až 20264302 a držené hn_* jednou; leave-one-family-out stejné rodiny jako K10-1; kombinace útok + porucha + šum 10× a XXXL jednou na konci. Soak musí od této fáze ukládat posteriory žebříku (`ladder_posteriors` v `networks.jsonl`), jinak ECE nejde změřit.

### Stav fáze (aktualizováno 2026-11-14 večer)

| úkol | stav |
|---|---|
| rešerše 12b | hotová |
| 1 konkurenční hypotézy a EVOI | modul `competing.rs` (hypotézy s předpověďmi, EVOI, zastavení podle ceny) a režim `hypotheses` v žebříku (změřené věrohodnosti, rozhodnutí podle ceny omylu); **EVOI ještě neřadí plán kontrol v žebříku** (plán zůstává pevný) a `verification_chain::assess` se nevolá přímo (žebřík používá jeho druhy kontrol, skupiny a ceny); kontroly TLS a DNS v žebříku **nezapojeny** |
| 2 sekvenční vážení | v `competing.rs` (skupiny, poloviční váha závislých, nic = váha 0) a v žebříku přes `hypotheses` |
| 3 žádost o chybějící data | `case_file::data_requests` (log, segment, senzor) + pokrytí senzorů; do reportu API nezapojeno |
| 4 retrospektivní vyhledávání | `retro.rs` (indikátor, pacient nula, časová osa, fáze, incidenty s příčinou); do soaku a pipeline nezapojeno |
| 5 znovuotevření a audit | `reassess.rs` (jen modul s testy) |
| 6 kalibrace, ECE, konformální | `conformal.rs` (třídně podmíněná), posteriory ukládá soak (`ladder_log`), `tools/k12_boundary.py` měří ECE a hranici automatizace; **konformální pokrytí na soak datech zatím neměřeno** |
| 7 spis případu | `case_file.rs` (modul s testy); do API nezapojeno |
| 8 forenzní žádosti | `forensic.rs` (broker, dvojí klíč, katalog, expirace, audit; testy) |
| strict_close (zavírání) | kontext a vyvrácení žebříkem; měření probíhá |

## 6) Cílová hodnota detekce: 100 % u pozorovatelných útoků (doplnění zadání)

Předregistrované minimum zůstává (K12-2: ≥ 90 %, dolní mez Wilson ≥ 85 % při n ≥ 50). **Cíl je 100 %** u útoků, jejichž toky přežily degradaci telemetrie (`diag.visible_flows` > 0). Minimum není důvod přestat: u každé rodiny po opravě se zapíše, co ji drží pod 100 %, a co je řešitelné (chybějící signál, vstup, pravidlo, kontrola), se dodělá, dokud to jde bez ceny na dvou pevných hranicích: **omylem zavřené = 0** a **FP poměr ≤ 1,15 proti k8ref**. Co principiálně nejde (útok není v telemetrii, obsahově nerozlišitelné), se zapíše kvantitativně (počty útoků a příčina).

Tabulka zbytků po rodinách (doplňuje se z `tools/k11_diag.py` na držených seedech; sloupce: n, detekce, detekce z útoků s viditelnými toky, zbytek podle příčiny a, b, c, řešitelné ano/ne, co by pomohlo):

| rodina | n | detekce | z viditelných | zbytek (a viditelné / b / c) | co drží pod 100 % | řešitelné |
|---|---|---|---|---|---|---|
| (vyplní se po měření na držených seedech) | | | | | | |

Hlášení blízkosti: pro každou rodinu uvedu rozdíl do 100 % v procentních bodech a dolní mez Wilson; souhrnně počet rodin nad 90 %, nad 95 % a na 100 % mezi pozorovatelnými útoky.

## 7) Výsledky fáze 1: politika zavírání (`strict_close`), seed 20263101, 40 sítí, druhé měření stejného seedu

Zdroje: `k11/k12-strict-vs-base.md`, `tools/k12_boundary.py`. Základ `hb` (preset), kandidát `sB` = `breadth` + `bulk_clear` + `strict_close` (zavření kontextem jen s identifikovanými zdroji, z nichž všechny patří záznamu, bez výjimky pro objem; vyvrácení žebříkem jen s pozitivním důkazem ze ≥ 2 nezávislých skupin, z toho aspoň jedna silná). Medziv rameno `sA` (jen kontext) ukázalo, že samotný kontext je jen menšina příčin: omylem zavřených útoků 26 → 22, hlavní příčinou je vyvrácení žebříkem.

| ukazatel | základ `hb` | kontext `sA` | kontext + žebřík `sB` |
|---|---|---|---|
| útoky s omylem zavřeným nálezem | 26 z 3 598 (0,72 %, horní mez 1,06 %) | 22 (0,61 %, 0,92 %) | **1 z 3 598 (0,03 %, horní mez 0,16 %)** |
| vyvrácení žebříkem: počet, z toho omylem | 809, 34 (4,2 %) | 806, 34 | **4, 0** (horní mez u 4 vzorků 49 %, nelze tvrdit nic) |
| zavření kontextem: počet, omylem (kontrafaktuál) | 23, 2 | 10, 1 | 10, 1 |
| zobrazené FP na síť-den | 10,47 | 11,67 | 11,73 (poměr 1,120 proti `hb`; ≤ 1,15 splněno) |
| zobrazených položek celkem | 61 289 | | 64 132 (+4,6 %) |
| detekce bezpečnostních útoků (rodiny, ne hn_*) | 85,6 | | 86,7 |
| potvrzení žebříkem, z nich neškodné | 14,5 % | 13,7 % | 10,2 % |

**Cena: analytické zatížení.** Vyvrácení žebříkem, které dřív zavřelo ~800 případů na 40 sítí (z nich 4,2 % omylem), se teď předává člověku: zobrazených položek je o 4,6 % víc a podíl případů žebříku předaných člověku je 85,7 % (základ 83,2 %). Tedy **žebřík sám zavírá téměř nic** (4 z 39 043). Cíl „0 omylem zavřených“ je splněn na tomto vzorku (1 pozorováno, ne 0), **zbylý jeden útok** je zavření kontextem `authorized_scanner` (kontrafaktuál 1 z 10; horní mez 40 % u tak malého vzorku). Příčinu zbylého případu jsem dál nerozebíral.

**Hranice automatizace v tomto stavu** (z `k12_boundary.py`, `sB`): autonomně rozhodnuto 14,3 % případů (potvrzení a vyvrácení), 85,7 % předáno člověku. Autonomní potvrzení jsou z 10,2 % neškodná (horní mez 11,0 %); ECE posteriorů 7,9 %, Brier 0,182. **Záruku horní meze omylu u autonomního zavření nelze dát**, protože autonomních zavření je jen 14 na 40 sítí (horní mez Wilson 1 z 10 je 40 %). Pro záruku ≤ 0,5 % by bylo potřeba aspoň ≈ 600 autonomních zavření bez omylu na jednu síť nebo sadu sítí.

Úprava poctivosti: o 0 omylem zavřených nelze mluvit; pozorován 1 z 3 598. Měření se opakovalo jen na jednom seedu (druhý seed `sA` jsem ukončil kvůli času), takže jde o ladicí, ne držený seed.

Rozbor zbylého jednoho případu (`sB`, síť 14): rodina `duplicate_ip_conflict` je provozní porucha (kategorie ops_fault), ne bezpečnostní útok; jeho nález `scan_attempts` zavřel kontext `authorized_scanner`, protože okno schváleného skeneru se překrývalo s poruchou (a s dvěma zálohami) a všechny zdroje nálezu patřily skeneru. Mezi bezpečnostními útoky (kategorie security) tedy v tomto vzorku nebyl žádný omylem zavřený; chyba je u poruchy, kterou schválené okno skeneru zakrylo. Dalším krokem by byl požadavek, aby kontext skeneru zavřel nález jen tehdy, když je i **cíl** nálezu v rozsahu záznamu (záznam skeneru dnes cíle nemá, `hosts` prázdné): nezpracováno.

## 8) Odchylky a poznámky ke vstupům TLS a DNS (měření `l0` a `l1`, seed 20261102, ladicí)

- Svět `--l7 on` je simulace s autorovými rozděleními (studie 12 a `soak/l7sim.rs`), **nekalibrovaná na veřejných datech**. Výsledky níže tedy říkají, co detektory dělají nad takto vyrobenými metadaty, ne že tak fungují na provozu. Kalibrace (část C) je nehotová.
- První verze `tls_rare_transfer` a `tls_novel_burst` měla jako druhý rys i „cíl zná nejvýš 2 hostitelé“. Na ladicím seedu to zobrazilo 46 až 54 % neškodných scénářů hn_cdn_update_download a hn_mail_newsletter_burst (vzrůst o 41 až 44 p. b.) a o 17 p. b. hn_nightly_cloud_backup_upload; v malé síti zná jméno málo hostů vždy. Rarita cíle byla odstraněna jako samostatný rys (zůstává jen jako okolnost v textu nálezu). Změna vznikla po pohledu na hn_* výsledky; z těchto tří scénářů jsou cdn a mail **ladicí**, ale **backup je držený** a tímto pohledem je částečně použit: výsledek na držených seedech u backup proto čtu s rezervou.
- Výsledek první verze (`l0` proti `l1`, 40 sítí): detekce rodin 85,9 → 87,7 %, bucket_mass_download +46,7 p. b., cloud_api_discovery_burst +38,5, dns_zone_enum_burst +53,8, exfil_cloud_storage_upload +50,0; FP na síť-den 8,38 → 9,55 (poměr 1,140).

## 9) Výsledky na ladicím seedu 20261102 (40 sítí, svět k10 s `--l7 on`), přírůstky po přepínačích

Všechna ramena mají `breadth`, `bulk_clear`, `strict_close`. FP je zobrazené FP na síť-den, „zavřeno omylem“ jsou útoky s omylem zavřeným nálezem (kontrafaktuál), hn_* je největší změna podílu zobrazených neškodných scénářů proti předchozímu rameni.

| rameno | přírůstek | detekce rodin (bez hn_*) | FP/síť-den | zavřeno omylem | hn_* nejvíc |
|---|---|---|---|---|---|
| `l0` | základ této řady (L7 svět zapnut, žádný L7 detektor) | 85,9 % | 8,38 | 1 | - |
| `l1` | + `l7_tls`, `l7_dns` (první verze s raritou cíle) | 87,7 % | 9,55 (1,140) | 1 | +44,4 p. b. (cdn), +40,7 (mail), +16,7 (backup) |
| `l2` | totéž bez rarity cíle jako rysu | 86,8 % | 8,41 (1,003) | 0 | 0,0 |
| `fin` | + `hypotheses` | 86,7 % | 8,43 (1,003) | 0 | 0,0 |
| `rd` | + `redisplay` | 86,8 % | 8,45 (1,002) | 0 | 0,0 |
| `ic` | `fin` + `icmp_payload` a DNS tunel (`dns_tunnel_names`) | 87,6 % | 8,43 (1,000) | 0 | (beze změny) |

Přírůstky po rodinách (ladicí seed, n = 10 až 20, intervaly široké): bucket_mass_download 13,3 → 33,3 % (`l2`), cloud_api_discovery_burst 7,7 → 15,4 %, dns_zone_enum_burst 7,7 → 61,5 %, exfil_icmp_payload 35,0 → 95,0 % (`ic`), c2_dns_txt_beacon 52,4 → 76,2 %, exfil_dns_slow 82,6 → 91,3 %.

**Co nepomohlo (poctivě):**
- **`hypotheses`** (režim konkurenčních hypotéz v žebříku): detekce a FP beze změny, ale **autonomně se rozhoduje jen 1,5 % případů** (základ `l2` 12,5 %), 98,5 % jde člověku, a ECE se **zhoršila** z 10,0 % na 13,5 %. Důvod: při poměru cen omylu 200 : 1 a měřených, slabých věrohodnostech žádná běžná kontrola nezmění akci (EVOI ≤ 0), takže se program po zásluze zastaví a předává. Nepoužívat v `recommended()`.
- **`redisplay`** (citlivější znovuzobrazení): žádný měřitelný přínos (credential_stuffing +1 případ); zbytky „nezobrazeno“ jsou z drtivé většiny `suppressed` (nález se připojil ke klíči, který už v paměti byl), ne chybějící signál.
- Zbylé „nezobrazeno, suppressed“ (např. exploit_attempt 6, port_scan_vertical 3, port_scan_horizontal 2, credential_stuffing 3) jsou případy, kdy útok splynul s dřívějším nálezem stejného klíče. Nabídla by se politika „nález s novým důkazem se zobrazí znovu“; jednoduchá varianta přes objem (`redisplay`) nepomohla, a složitější by znamenala další zobrazené položky bez záruky.

Tabulka zbytků po rodinách (nástroj `tools/k12_residual.py`) pro držené seedy je v `k12/held.md` po dokončení měření.

## 10) Výsledky na držených seedech (jednou) proti předregistrovaným prahům

Zdroj: `k12/held.md` (20264101 a 20264102, 80 sítí; dva ze šesti předregistrovaných seedů). Kandidát = `breadth`, `bulk_clear`, `strict_close`, `l7_tls`, `l7_dns`, `icmp_payload`.

| práh | výsledek | stav |
|---|---|---|
| K12-1 omylem zavřené = 0, horní mez uvést | základ 34 z 5 506 (0,62 %, horní mez 0,86 %), kandidát **4 z 5 506 (0,07 %, horní mez 0,19 %)**; všechny čtyři v jedné síti (22 seedu 4102) s ~100 překrývajícími se neškodnými událostmi, ne přes `auto_closures` ani vyvrácení žebříkem (příčinu jsem nerozebral) | **nesplněno** (4, ne 0), ale 8,5× méně |
| K12-2 detekce ≥ 90 % u každé rodiny | z útoků s viditelnými toky: ze 78 rodin (n ≥ 20) je **50 nad 90 %, 35 nad 95 %, 14 na 100 %**; 28 rodin pod 90 % (výčet v `k12/held.md`, oddíl C) | **nesplněno** |
| K12-3 FP poměr ≤ 1,15 | 9,05 → 9,55, poměr **1,056** | splněno |
| K12-4 hn_* držené ≤ +10 p. b. | backup +1,7, db replikace +1,6, snmp −0,8, heslo 0,0; ladicí cdn +0,9, mail +2,7 | splněno |
| K12-5 paniky, invarianty, chráněná zavření | 0 | splněno |
| K12-6 determinismus (`soak verify`) | **neověřeno** (viz oddíl 11) | nehotovo |
| K12-7 fuzz parsery | `l7::tests::fuzz_parsers_never_panic`, 20 000 vstupů | splněno |
| K12-8 `no_memory` | zelený (spuštěn s plnými testy, oddíl 11) | viz oddíl 11 |
| K12-9 LOFO a leave-one-tactic-out nových detektorů | částečně: detektory nemají ladění po rodinách, přenos je viditelný u rodin, pro které nebyly určeny (viz tabulka přenosu v `k12/held.md`), ale **formální LOFO a LOTO vyhodnocení po taktikách jsem neprovedl** | nehotovo |
| K12-10 žebřík: správně rozhodnuté, ECE | autonomně 16,0 % případů, z potvrzení 6,3 % neškodných (horní mez 6,9 %), ECE 9,5 % (> 0,10 splněno těsně); vyvrácení jen 6, z nich 0 omylem (horní mez 39 %, nelze tvrdit) | ECE splněno těsně; správnost nelze tvrdit z 6 případů |
| K12-14, K12-15 záruky autonomního rozhodnutí | **nelze dát**: autonomních zavření je 6 vyvrácení žebříkem a 0 kontextem na 5 506 útoků, horní mez Wilson u 0 z 6 je 39 % | záruka nedosažena, rozhoduje člověk |
| K12-17 konformální pokrytí | `conformal.rs` s testem na syntetických datech, **na soak datech neměřeno** (`ladder_log` se ukládá, vyhodnocovací tool nenapsán) | nehotovo |
| K12-18 čas k rozhodnutí | medián (průměr) 1,66 → 1,68 cyklu | beze změny |
| K12-19 incidenty (čistota, nálezů na incident, čas k prvnímu) | `retro.rs` je modul s testy; `incident_id` v generátoru a měření **nebylo provedeno** | nehotovo |
| K12-20 oddělení útoku od poruchy | neměřeno | nehotovo |
| K12-21 audit autonomních rozhodnutí | zavření kontextem se loguje (`salticus::audit`), `reassess.rs` má audit; zapojení do běhu a kontrola 100 % pokrytí neměřena | částečně |
| K12-22 forenzní žádost bez schválení | `forensic.rs`, test | splněno (modul) |

### Před a po po rodinách (držené seedy, základ → kandidát)

| rodina | základ | kandidát | poznámka |
|---|---:|---:|---|
| exfil_alt_protocol_ftp | 12,5 | 79,2 | `bulk_clear` |
| drive_by_bulk_download | 6,7 | 43,3 | `bulk_clear` |
| bucket_mass_download | 13,8 | 34,5 | `l7_tls` |
| cloud_api_discovery_burst | 17,2 | 41,4 | `l7_tls` |
| clicks_to_rare_destination | 4,5 | 4,5 | bez změny |
| port_scan_horizontal | 75,9 | 76,6 | |
| c2_beacon | 85,1 | 87,8 | |
| exploit_attempt, exfiltration, port_scan_vertical, credential_stuffing, cryptomining | beze změny | | |
| celkem bezpečnostní rodiny | 84,1 | 87,2 | |

Pozn.: detekce `dns_zone_enum_burst`, `exfil_icmp_payload`, `c2_dns_txt_beacon` na držených seedech je v `k12/held.md` v tabulce zbytků (75,0, ≥ 90 a 75,0 % z viditelných); na ladicím seedu byla 61,5, 95,0 a 76,2 %.

### Co drží rodiny pod 100 % (zbytky, kandidát, držené seedy)

Z `k12/held.md` oddíl C, hlavní příčiny v pořadí podle počtu zmeškaných viditelných útoků:
1. **Nález byl, ale splynul s dřívějším nálezem téhož klíče a nezobrazil se (`suppressed`)**: port_scan_horizontal 18, smb_sweep_ext 6, mqtt_probe_ext 7, exploit_attempt 6, c2_beacon 4. Řešitelné jen politikou „nový důkaz = znovu zobrazit“; jednoduchý pokus přes objem (`redisplay`) nepomohl, další pokus by znamenal víc zobrazených položek bez změřené záruky.
2. **Nepřipsáno / typ nálezu (c)**: exploit_attempt 77 a c2_beacon 40 útoků je zachyceno nálezem jiného typu, než se očekává; do detekce se počítají.
3. **Útok bez signálu v tocích (a viditelné)**: clicks_to_rare_destination 17 z 22 (2 až 12 malých toků na nový cíl; obsahově nerozlišitelné od kliknutí v telemetrii toků; pomohla by webová a DNS pověst cíle), exfil_cloud_storage_upload 11, bucket_mass_download 15, drive_by 14 (šifrované stažení od cíle, který používá standardní otisk klienta: **podle návrhu simulace** je to útočník žijící z krajiny a L7 rysy ho nerozliší).
4. **Slepé útoky (`visible_flows = 0`)**: nezapočítávají se do „z viditelných“; počty po rodinách jsou v tabulce zbytků.
