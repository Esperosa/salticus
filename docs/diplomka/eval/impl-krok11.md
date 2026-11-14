# Implementace, krok 11: cílené opravy detekce po rodinách

Datum 2026-11-14. Navazuje na kroky 9 a 10. Diagnostika: `k11/diagnoza.md`. Projekt: Salticus.

Poctivost o pořadí: tato předregistrace vznikla poté, co byly napsány přepínače a spuštěno první ladicí měření kandidáta (`c1`, seedy 20261102 a 20261103), ale **dříve, než jsem viděl jeho výsledky**. Prahy detektorů (níže) jsou hodnoty z návrhu, nebyly dosud upraveny. Jakákoli změna prahu po tomto zápisu se píše do sekce „Odchylky“ i s důvodem. Držené seedy se nespustily.

## A) Co se opravuje (každá oprava za vlastním přepínačem, výchozí vypnuto)

| přepínač | vlastnost (abstraktní, bez rodiny, seedu a adresy) | cílové rodiny | práh (návrh) |
|---|---|---|---|
| `bulk_novel` (`novel_bulk_transfer`) | zralý vnitřní host (≥ 12 h v profilu) má první vztah s vnějším protějškem, který profil nezná ani jako kandidáta a který nezná flotila (≤ 2 vnitřní hosté za 7 dní), a čistý přenos (stažení nebo nahrání) v prvním okně je ≥ 2 MB | drive_by_bulk_download, bucket_mass_download, exfil_alt_protocol_ftp | 2,0 MB |
| `peer_burst` (`novel_peer_burst`) | totéž první-vztah pravidlo, ale ≥ 6 toků do 300 s | cloud_api_discovery_burst, clicks_to_rare_destination | 6 toků / 300 s |
| `scan_fresh` (`scan_attempts`) | vnější zdroj (není ve vnitřním inventáři) bez jediného úspěšného spojení v okně, a 4 distinktní cíle za 24 h místo 8 | port_scan_horizontal | 4 cíle |

Nové typy nálezů `novel_bulk_transfer` a `novel_peer_burst` se řadí k novosti: nikdy se automaticky nezavírají (stejná ochrana jako `novel_persistent_peer`), kontext je nevysvětlí. Signály vycházejí z toků, které engine už má (odchozí toky vrstvy chování, profil hostu, prevalence cíle, neúspěšné pokusy zdroje). Žádný seed ani adresa v kódu (ověřuje `no_memory`).

## B) Co se neopravuje (a proč), do registru slepých míst

- `dns_zone_enum_burst`: provoz jde ven→dovnitř, vrstva chování inbound toky nedostává. Vstup (inbound toky ve vrstvě chování) chybí: kategorie b.
- `port_scan_vertical`, `credential_stuffing`, `exfiltration`, `c2_beacon`, `exploit_attempt`: většina zbylého zmeškání je slepá (výpadek senzoru, slepá podsíť) nebo typ nálezu; zapsáno jako c (potřebná nepoškozená telemetrie, u exploitu aplikační záznamy, DNS a TLS).
- Krátké beacony (< 12 spojení): RQ4-014, skóre je prázdné; kategorie c.

## C) Prahy (předregistrované, hodnoty se po prvním měření nemění)

| práh | definice | splněno, když |
|---|---|---|
| K11-1 | detekce každé opravené rodiny na držených seedech | ≥ 90 % a dolní mez Wilsona ≥ 85 % tam, kde n ≥ 50; jinak se uvede detekce a „nedostatek dat“. Nesplněné rodiny jdou do registru |
| K11-2 | zobrazené FP na síť-den, kandidát proti základu na stejných seedech (svět k10) | poměr ≤ 1,15 (celkem), a zvlášť neškodné změny hn_* nesmí zvýšit zobrazení víc než o 10 p. b. |
| K11-3 | útoky s omylem zavřeným nálezem | ≤ 2,2 % |
| K11-4 | chráněná automatická zavření | 0 |
| K11-5 | paniky a porušené invarianty | 0 |
| K11-6 | determinismus | stejný seed, stejný výsledek (test epizody) |
| K11-7 | zákaz paměti | `no_memory` zelený |
| K11-8 | generalizace (LOFO) | viz E |

Základ = stejná binárka bez nových přepínačů a bez `breadth` (preset `recommended`, ekvivalent k8ref). Kandidát = `breadth` plus nové přepínače. Dopad samotného `breadth` je znám z kroku 10 (poměr FP 1,048), a proto se u kandidáta uvádí i rameno „jen `breadth`“ (`d1`) na stejných seedech, aby bylo vidět přírůstek nových přepínačů.

## D) Seedy

- Ladění: 20261102 a 20261103 (diagnostika a první kandidát), případně 20261104, 20262301 a 20262302 pro potvrzení ladění (kroky 9 a 10 je používají).
- **Nové držené seedy** (nikdo je nepoužil, pustí se jednou na konci, základ a kandidát, svět k10, 40 sítí každý): **20263101, 20263102, 20263201, 20263202, 20263301, 20263302**.
- Kontrola, že tyto seedy nejsou v kódu ani v dřívějších řadách: `grep` v `src` a v `F:/Projekty/bakula-soak`.

## E) Leave-one-family-out pro nové detektory

Prahy se nefitují na rodinu: jsou zvoleny z úvahy o vlastnosti (2 MB čistého přenosu, 6 toků do 5 minut, 4 cíle). LOFO se proto vyhodnotí takto: (1) detekce rodin, **pro které detektor nebyl určen** (exfil_cloud_storage_upload, insider_after_hours_cloud_sync, data_staging_smb_internal, mail_forward_smtp_exfil, c2_cloud_storage_dead_drop, c2_https_legit_service a další) základ proti kandidátovi na držených seedech: kladný přírůstek ukazuje, že vlastnost se přenáší; (2) tabulka přírůstku po rodinách, aby bylo vidět, kdo se zhoršil. Přiznané omezení: prahy jsem volil po prohlédnutí tabulky diagnostiky, takže cílové rodiny nejsou nezávislé; nezávislé jsou jen rodiny mimo cíl a držené seedy.

## F) Pořadí měření

Jedno rameno najednou, Idle priorita, 6 vláken, PID 118652 se nedotýká (viz priority: Idle). Ladění: `kb` (základ) a `c1` (kandidát všechny tři přepínače) na 20261102 a 20261103; podle výsledku případné jednotlivé přepínače po jednom. Držené seedy až na konci, jednou.

## G) Odchylky a poznámky

(zapisuje se průběžně)

### G1) Odchylky po prvním ladicím měření (zapsáno před spuštěním držených seedů)

Ladění na 20261102 a 20261103 (základ `kb`, kandidát `c1` se všemi třemi přepínači), potom izolace na 20261102 (`cb`, `cp`, `cn`). Prahy detektorů (2 MB, 6 toků / 300 s, 4 cíle) se **nezměnily**. Změnil se tvar oprav:

1. **Přibyl přepínač `bulk_clear`** (`novel_bulk_transfer` jen pro přenos po nešifrovaných portech 21, 23, 25, 80, 8080). Důvod: `bulk_novel` (všechny porty) zobrazil i hard-negative hn_cdn_update_download (11,5 → 73,4 %) a hn_nightly_cloud_backup_upload (60,5 → 86,4 %), tedy poměr ≈ 2 neškodné ku 1 útoku; po šifrovaných portech je stažení z nového CDN od nového bucketu v tokách nerozlišitelné. Nešifrovaný objemový přenos na první vztah je abstraktní rys (ne rodina), ale zvolil jsem ho po pohledu na hn_* výsledky, takže hn_* nejsou u tohoto rozhodnutí nezávislé.
2. **`scan_fresh` nepomohl** na ladicích seedech (port_scan_horizontal +2,0 p. b. v kandidátu c1 se vším, v izolaci `cb` 0, a `scan_fresh` v `cb` není zapnut; v `c1` je zapnut a rozdíl +2,0 p. b. patří i ostatním přepínačům). Do držených seedů ho jako samostatnou opravu nenesu.
3. **`peer_burst` zobrazil hn_mail_newsletter_burst** (5,1 → 66,1 %) výměnou za cloud_api_discovery_burst (7,7 → 61,5 %). Rozlišit je jde jen portem (587 proti 443), což by bylo ladění na hard-negative scénář; neprovádím.

Kandidáti na držených seedech: **A = `breadth` + `bulk_clear`** (hlavní kandidát), **B = `breadth` + `bulk_novel` + `peer_burst` + `scan_fresh`** (agresivní, kvůli záznamu trade-offu). Základ = bez nových přepínačů a bez `breadth` (preset `recommended`). Pořadí běhů: základ na všech šesti seedech, potom A, potom B; vždy jedno rameno.

### G2) Další odchylky při držených seedech

- Kandidát B se pustil jen na dvou držených seedech (20263101, 20263102) z časových důvodů; kandidát A a základ na všech šesti. Jeden běh B se nejdřív omylem přeskočil (název ramene `hB` kolidoval s `hb` na souborovém systému bez rozlišení velikosti písmen); B se pustil znovu pod názvem `hfull`, bez změny kódu a prahů.
- Intervaly Wilson v tabulkách jsou po útocích, ne po sítích (útoky ve stejné síti nejsou nezávislé), takže skutečné intervaly jsou o něco širší.

## H) Výsledky na držených seedech (jednou)

Zdroje: `k11/held-A.md` (6 seedů, 240 sítí), `k11/held-B.md` (2 seedy, 80 sítí), ladění `k11/ladeni-c1.md`. Základ = preset `recommended`, svět k10.

### H1) Opravené rodiny: před a po proti předregistrovaným prahům

| rodina | n (A) | základ | A (`breadth` + `bulk_clear`) | B (vše, 2 seedy) | práh K11-1 (≥ 90 %, dolní mez ≥ 85 %) |
|---|---:|---|---|---|---|
| drive_by_bulk_download | 75 | 8,0 | **52,0** (40,9 až 62,9) | 52,0 (n = 25) | **nesplněno** |
| exfil_alt_protocol_ftp | 76 | 18,4 | **78,9** (68,5 až 86,6) | 76,9 (n = 26) | **nesplněno** |
| bucket_mass_download | 90 | 5,6 | 6,7 (3,1 až 13,8) | 80,8 (62,1 až 91,5), n = 26 | **nesplněno** (A) |
| cloud_api_discovery_burst | 88 | 13,6 | 13,6 | 80,0 (64,1 až 90,0), n = 35 | **nesplněno** (A) |
| clicks_to_rare_destination | 84 | 9,5 | 9,5 | 19,4 (9,2 až 36,3) | **nesplněno** |
| port_scan_horizontal | 560 | 85,5 | 85,4 | 91,3 (86,5 až 94,5), základ 88,8 na stejných seedech | A: nesplněno; B: nad 90 %, dolní mez 86,5 (n = 196), ale zlepšení +2,6 p. b. nelze odlišit od šumu a ostatní přepínače B ho nezpůsobují přímo |

Žádná z šesti rodin nesplnila K11-1 v kandidátu A. Rodiny, které se pohnuly (drive_by, exfil_ftp), se přiblížily, ale nedosáhly 90 %: část útoků je pod 2 MB nebo slepá (diagnoza.md).

### H2) FP, zavření, bezpečnost

| práh | A (6 seedů) | B (2 seedy) | stav |
|---|---|---|---|
| K11-2 zobrazené FP na síť-den, poměr proti základu | 9,29 → 10,04, **1,081** | 8,98 → 10,26, **1,142** | splněno (≤ 1,15); u A patří většina přírůstku samotnému `breadth` (na ladicím seedu 20261102: základ 7,52, `breadth` 7,89, `breadth` + `bulk_clear` 7,89, tedy `bulk_clear` přidal 0,00) |
| K11-2 neškodné změny hn_* (změna zobrazení ≤ 10 p. b.) | splněno: největší změna +0,7 p. b. | **nesplněno**: hn_cdn_update_download +69,7, hn_mail_newsletter_burst +70,6, hn_nightly_cloud_backup_upload +29,2 | A ano, B ne |
| K11-3 omylem zavřeno | 0,7 % (148 útoků) | 0,6 % | splněno |
| K11-4 chráněná zavření | 0 | 0 | splněno |
| K11-5 paniky a invarianty | 0 / 0 | 0 / 0 | splněno |
| K11-6 determinismus | testy epizod zelené (výchozí vypnuto se stavem nemění); běh `soak verify` s novými přepínači jsem nepustil | | částečně |
| K11-7 zákaz paměti | `soak::no_memory` zelený | | splněno |
| K11-8 přenos (LOFO) | rodiny, pro které `bulk_clear` nebyl určen: mail_forward_smtp_exfil +22,9 p. b. (61,4 → 84,3), exfil_over_c2_trickle +18,1 (66,3 → 84,3), exfil_cloud_storage_upload +7,3; zhoršení do −1,3 p. b. (imap_spray, smb_login_failures, dc_replication_from_workstation) v mezích šumu | u B navíc exfil_cloud_storage_upload +45,2 | částečně: přenos je kladný u úniků po nešifrovaných portech (SMTP, nešifrovaný C2), ne obecně |

Testy: celé `cargo test --lib`: 558 prošlo, 5 selhalo (`broker::*`, vyžadují Redis; nesouvisí). Nové testy `behavior::oneshot` a `scan_fresh_lowers_threshold_only_for_unknown_source_without_success` jsou zelené.

### H3) Co se nepodařilo a proč

1. **K11-1 se nepodařilo u žádné ze šesti rodin v A.** `bulk_clear` pohnul jen rodiny po nešifrovaných portech (drive_by 80, exfil_ftp 21): +44 a +60,5 p. b.
2. **Šifrované hromadné stažení (bucket_mass_download, 443) a shluk toků na nový cíl (cloud_api_discovery_burst, clicks_to_rare_destination) se bez ceny v neškodných změnách opravit nedá.** `bulk_novel` a `peer_burst` zvedly detekci na 74 až 81 % a 61 až 80 %, ale zobrazily 70 % hn_cdn_update_download, 70 % hn_mail_newsletter_burst a +29 p. b. hn_nightly_cloud_backup_upload. Tvary toků jsou stejné (jeden host, první vztah, velký přenos nebo shluk); rozlišuje je jen port nebo účel, a ladit na port hard-negative scénáře by bylo přizpůsobení testu. Vstup, který by pomohl: záznamy TLS (SNI, certifikát, ASN cíle) a DNS (pověst domény, stáří).
3. **`scan_fresh` bez prokazatelného přínosu**: port_scan_horizontal v B +2,6 p. b., v A (bez `scan_fresh`) −0,2; zlepšení se nepřipisuje přepínači. Vnější sken s 4 až 7 cíli v těchto datech často končí jako „nález existoval i bez útoku“ (kategorie c nepřipsáno), ne jako chybějící nález. Neprošlo.
4. **Velké rodiny se neopravovaly** (diagnoza.md): většina zbylého zmeškání je slepá (výpadek senzoru, slepé podsítě) nebo jde o typ nálezu, ne o chybějící signál.
5. **dns_zone_enum_burst** neopravena (provoz ven→dovnitř mimo vrstvu chování): vstup chybí.

## I) Aktualizovaný registr slepých míst (krok 11)

| místo | kategorie | co chybí |
|---|---|---|
| Útoky, jejichž toky nedorazily do telemetrie (výpadek senzoru, slepá podsíť, ztráta toků); port_scan_vertical 12 z 20 zmeškaných, credential_stuffing 4 z 13, exfiltration 3 z 9 | c (otevřené, mimo dosah detekce) | nepoškozená telemetrie; měřeno poprvé v kroku 11 (`diag.visible_flows`) |
| Šifrované hromadné stažení z prvně viděného cíle (bucket_mass_download, drive-by po 443) a shluk toků na nový šifrovaný cíl (cloud_api_discovery_burst, clicks_to_rare_destination) | b (zmírněno jen za cenu zobrazení neškodných: viz H3 bod 2) | TLS a DNS záznamy (SNI, pověst a stáří domény, ASN) |
| Nešifrované hromadné stažení a únik na první vztah | b (zmírněno, `bulk_clear`: drive_by 52 %, exfil_ftp 79 %) | zbytek je pod 2 MB nebo slepý |
| dns_zone_enum_burst (vnější zdroj → DNS sítě) | b | inbound toky ve vrstvě chování (`behavior` dostává jen odchozí a vnitřní) |
| exploit_attempt, c2_beacon s krátkým oknem | c | aplikační záznamy (HTTP, TLS) a delší pozorování (RQ4-014, min. 12 spojení) |
| Typ nálezu u exploit_attempt, c2_beacon, ssh_bruteforce (zachyceno, ale jiným typem) | c | hodnocení typu je přísnější než detekce |
| Vnější sken s 4 až 7 cíli (`scan_fresh`) | c (nepřínosné v tomto světě) | nález bez útoku téhož zdroje a cíle |

## J) Návrh pro `recommended()` (jen s důkazem)

- **Zapnout `bulk_clear`**: na držených seedech +44 a +60,5 p. b. u dvou cílových rodin, přenos +18 až +23 p. b. na dvou nezacílených rodinách, hn_* beze změny (největší +0,7 p. b.), FP na síť-den beze změny proti `breadth` (ladicí seed), omylem zavřeno 0,7 %, 0 chráněných zavření. Důkaz ze 6 držených seedů a 240 sítí. Podmínka: současně zapnutý `breadth` (jeho dopad na FP je 1,044 až 1,048 z kroků 9 a 10) nebo i bez něj (nezávislý: `bulk_clear` stojí jen na profilu a odchozích tocích); samostatné měření `bulk_clear` bez `breadth` na držených seedech neproběhlo.
- **Nezapínat `bulk_novel` a `peer_burst`**: zobrazují 70 % neškodných hn_cdn_update_download a hn_mail_newsletter_burst. Mají smysl jen jako volitelný režim vyšší citlivosti s vědomým přijetím cizích falešných poplachů.
- **Nezapínat `scan_fresh`**: bez přínosu.
