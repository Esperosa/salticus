# Krok 13: reálná data, incidenty a posun k 100 % (předregistrace a stav)

Zadáno 2026-11-15. Omezení: proces Idle, max 6 vláken, jedno rameno, nic se nepushuje, commity lokálně bez stopy nástroje, data do `F:\Projekty\bakula-datasets`, licence ověřit před stažením, žádné registrace ani formuláře, `audit-pokryti.md` se nekomituje.

## Předregistrace (před kódem)

**Hypotézy a prahy**
- H1 (kalibrace): po odvození rozdělení z reálných logů (NXDOMAIN, TXT, délka a entropie jmen, SNI, stáří certifikátů, self-signed) se parametry pozadí simulátoru dostanou do pásma ±2× od reálné hodnoty u každé veličiny, kterou zdroj pokrývá. Co zdroj nepokrývá, se nekalibruje a zapíše se jako nekalibrované. Kalibrace se nesmí opírat o jediný host (min. 3 nezávislé zdroje na veličinu, jinak jen „orientační“).
- H2 (incidenty): nové seskupení za přepínačem `incident_v2` zvýší čistotu seskupení ze 59 % (nejlepší stávající, odstup 30 min) na ≥ 80 % na ladicím seedu a drží ≥ 70 % na držených; nálezů na incident nesmí klesnout pod 2 (jinak triviální řešení „každý nález zvlášť“); čistota se počítá stejnou metrikou jako dosud (podíl nálezů největší pravdy; nepřipsaný nález = vlastní štítek). Cíl ≥ 90 % z zadání se hlásí zvlášť a nepovažuje se za splněný, pokud ho nedosáhneme na držených.
- H3 (posun k 100 %): opravy jen takové, které mají oporu v reálných datech nebo v logice detektoru, ne ladění na testovací scénář. Stráže: omylem zavřené = 0 (horní mez se hlásí), FP poměr ≤ 1,15 proti základu, hn_* (hard-negative) hlášené zvlášť pro ladicí a držené seedy.
- H4 (reálné přehrání): pcap → Zeek → Salticus se změří u každého zpracovaného datasetu na úrovni hostů; rozdíl proti simulaci se hlásí kvalitativně, protože reálné pcapy nemají štítky incidentů v našem smyslu (jen botnet vs. normální host).

**Datová pravidla.** Nové držené seedy: `20265101, 20265102, 20265201, 20265202` (nikdy nepoužity, použít jednou, na konci). Ladění jen na `20261102` a `20261103`. LOFO pro nové detektory se hlásí tak, že každý detektor se vypne a měří se ztráta po rodinách; formální přeladění po rodinách není, pokud nejsou parametry po rodinách.

**Licence.** CTU-13 (Stratosphere IPS): CC-BY (stránka stratosphereips.org, ověřeno 2026-11-15), nutná citace Garcia et al. 2014. CTU-Normal-20: README bez uvedené licence, použito jen lokálně a pouze pro statistiky. CIRA-CIC-DoHBrw-2020 a CIC-Bell-DNS2021: text licence na unb.ca dovoluje redistribuci s citací, ale stažení vyžaduje formulář/registraci u UNB, což je vyloučeno; **nezpracováno**. MAWI: licenci neověřeno, nestaženo.

## Tabulka stavu

| bod | stav |
|---|---|
| 0 předregistrace a licence | hotovo (tento dokument) |
| 1 reálná data a kalibrace | rozpracováno: stažené CTU-13 pcapy 42, 43, 46, 54 (CC-BY). Zeek vydal logy jen pro 43 a 46 (1005 a 163 DNS řádků, 43 a 72 TLS); u 42 a 54 žádné logy dnes nevznikly (příčina neprověřena). Nástroj `tools/k13_real_stats.py`. Pro kalibraci chybí zdroje: dosud 3 zdroje (Normal-20, 43, 46) a jen s botnet hostem, tedy veličiny jsou orientační; **simulátor zatím nekalibrován** |
| 2 reálné přehrání | nezačato |
| 3 incidenty | nezačato |
| 4 posun k 100 % | nezačato (vstup: rodiny pod 50 % po kandidátu viz ladicí matice k13m) |
| 5 držené seedy, LOFO, souhrn | nezačato |

## Naměřeno do tohoto bodu (reálné zdroje, Zeek)

| zdroj | DNS řádků | NXDOMAIN | TXT/NULL | AAAA | TLS spojení | bez SNI | self-signed x509 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CTU-Normal-20 (normální host, 3 h) | 15 089 | 0,013 % | 0 | 24,5 % | 2 464 | 1,5 % | 3,0 % |
| CTU-13 botnet 43 (Neris) | 1 005 | 0 | 0 | 0 | 43 | 97,7 % | 5,6 % |
| CTU-13 botnet 46 (fast-flux) | 163 | 2,0 % | 0 | 0 | 72 | 100 % | 0 |

Pozorování: botnetové TLS je téměř vždy bez SNI (98 až 100 %) proti 1,5 % u normálního hosta, tedy „TLS bez SNI“ je u reálných botnetů silný rys; simulace ho má u útoku, ale pozadí bez SNI by mělo být ~1,5 %. NXDOMAIN je i u botnetů nízký (≤ 2 %), tj. simulační pozadí 5 % NXDOMAIN je nadsazené. Tři zdroje stále neumožňují kalibraci distribucí (zdroje jsou malé a jednoúčelové).

## Protokol měření (závazný od 2026-11-15, schváleno uživatelem)

Platí pro zbytek kroku 13 a pro krok 14. Porovnání verzí se nedělá jedním seedem, ale maticí.

- **Matice.** 10 seedů x 3 konfigurace sítě: small = Soho, Smb, IotHeavy; medium = Enterprise, Campus, Hospital, Industrial; large = Datacenter, Cloud, Metro; XXXL a XXL se hlásí zvlášť jako stres (`size_class`). Konfiguraci generátor neumí vynutit, odvozuje se po běhu z archetypu sítě (`tools/k13_matrix.py`, `config_of`); sítí na buňku je tedy tolik, kolik jich seed vylosoval.
- **Cíl rozsahu.** 600 až 1 000 sítí na rameno. **Nesplněno**: stroj dává ~1 síť za minutu při 6 vláknech (Idle), tj. 600 sítí = ~10 h na rameno. Zvolený rozsah a stav jsou v tabulce níže; maticová verze se pouští po částech.
- **Párování.** Základ a kandidát na stejných seedech, stejných sítích (`run_seed`, `network_id`), liší se jen přepínačem (`--v3-on`). Nepárové sítě se vynechají a spočtou. Běhy s různými seedy se nikdy nesrovnávají.
- **Jednotka analýzy** je síť. Poměrové ukazatele jsou součty přes sítě (poměr součtů). Intervaly 95 %: bootstrap po sítích stratifikovaný po seed x konfigurace, B = 2000, pevný seed, stejné vzorkování pro obě ramena; Wilson jen doplňkově. Hlásí se celek, konfigurace, rozptyl mezi seedy a rodiny zvlášť.
- **Dvě sady seedů.** Ladicí (smí se ladit): 20261102, 20261103, 20266101, 20266102, 20266103, 20266104, 20266105, 20266106, 20266107, 20266108. Držené (zapsáno dopředu, použít jednou na konci, nikdy nepoužity): 20265101, 20265102, 20265201, 20265202, 20265301, 20265302, 20265401, 20265402, 20265501, 20265502. hn_* ladicí (hn_cdn_update_download, hn_mail_newsletter_burst, hn_admin_bulk_ssh, hn_authorized_internal_scan) a držené (hn_nightly_cloud_backup_upload, hn_db_replication_bulk, hn_monitoring_snmp_sweep, hn_password_sync_periodic) zvlášť jako dosud.
- **Rozsah (skutečný, upraveno 2026-11-15 podle výkonu stroje, ~3 min na síť při 6 vláknech Idle):** ladicí sada seed 20261102 = 20 sítí, ostatních devět seedů po 8 sítích = 92 sítí na rameno; držená sada 10 seedů po 8 sítích = 80 sítí na rameno. Cíl 600 až 1 000 sítí **nesplněn** (potřeboval by ~30 h na rameno). Tabulky po konfiguracích mají proto malé buňky (kolem 3 sítí na seed x konfiguraci); intervaly to ukazují a závěry jsou orientační, dokud se matice nerozšíří.
- **Pořadí běhů (skripty v `F:\work-tmp\k13
uns3b.ps1`, `runs4.ps1`, `runs5.ps1`):** ladicí base/cand (`k13m`), ladicí mixy `--mix on` (`k13mix`), držené base/cand, držené mixy, LOFO po detektorech (`l7_tls`, `l7_dns`, `icmp_payload`; rameno = kandidát bez jednoho detektoru). Držená část se spouští až po rozhodnutí o kandidátu.
- **Dlouhé běhy** (soak 72 h) jen jako test stability a objemu, ne pro porovnání verzí.
- **Nástroj:** `tools/k13_matrix.py --families TSV --base DIRS --cand DIRS` (párové srovnání po sítích, tabulky po konfiguracích, seedech a rodinách). Stav: viz „Stav matice“ níže.

## Dodatek A a B (zadáno 2026-11-15): řízené mixy a katalog provozních incidentů. Předregistrace před kódem

Platí protokol měření výše (matice seed x konfigurace, párově, bootstrap po sítích) a stejná omezení.

**A. Řízené mixy.** Plánovač mixů umístí do jednoho okna s řízeným překryvem dvojice a trojice událostí (útok+útok, útok+porucha, útok+neškodná změna, porucha+porucha), s řízenou frekvencí po dvojicích (matice dvojic, každá dvojice stejně často, ne náhodný souběh). Každá událost nese `incident_id` a vztah k ostatním: `common_cause` (společná příčina), `concurrent` (souběh bez vazby), `consequence` (následek). Prahy:
- A1 detekce složek: každá složka mixu je zobrazena (kontrafaktuálně jako dosud) nejméně v 90 % relativně k téže složce samotné (pokles ≤ 10 %), hlásí se po dvojicích a po složkách.
- A2 omylem zavřené složky = 0 (horní mez Wilson se hlásí).
- A3 čistota seskupení do incidentů na oknech mixů ≥ 80 % (stejná metrika jako dosud, vlastní štítek pro nepřipsané nálezy) a nálezů na incident ≥ 2; zvlášť se hlásí úplnost (podíl dvojic nálezů téže události ve stejném incidentu), aby čistotu nešlo získat roztříštěním.
- A4 chybné spojení: podíl incidentů, které slučují události bez příčinné vazby (`concurrent`), ≤ 15 %; podíl incidentů se společnou příčinou rozdělených na víc incidentů se hlásí (cíl ≤ 30 %).
- A5 oddělení útoku od poruchy v mixech: správná kategorie složky (útok / porucha / neškodná změna) u ≥ 90 % zobrazených složek na ladicích seedech, ≥ 85 % na držených; hlásí se po dvojicích.

**B. Katalog provozních incidentů.** Katalog je strojově čitelný (`data/incident-catalog.json`, verzovaný, se zdroji) a obsahuje nejméně 60 typů se strukturou: id, název, kategorie (útok / porucha / neškodná změna / nejednoznačné), příčina, projev v tocích, DNS, TLS, DHCP, ARP, SNMP, syslog a endpointu, typická záměna s útokem, doporučená kontrola, závažnost, kdo řeší, zdroje a odkaz na generátor (`sim_variant`) nebo údaj, že generátor chybí. Každé tvrzení o projevu se opírá o zdroj (RFC, dokumentace výrobce, postmortem) nebo je označeno `assumption`. Prahy:
- B1 pokrytí: katalog ≥ 60 typů; typů s generátorem v simulátoru a s ground truth ≥ 60 % katalogu v tomto kroku (ostatní zapsat jako mezeru, ne skrývat).
- B2 správná kategorie (útok / porucha / neškodná změna) u zobrazených nálezů typů s generátorem ≥ 90 % na ladicích, ≥ 85 % na držených seedech, po typech.
- B3 útok maskovaný jako porucha zařazený jako porucha ≤ 10 %; porucha maskovaná jako útok zařazená jako útok ≤ 10 % (po typech i celkem).
- B4 porucha se nikdy nezavírá jen proto, že není útok: počet poruch zavřených automaticky z tohoto důvodu = 0.
- B5 FP na síť-den ≤ 1,15 proti základu; omylem zavřené útoky = 0 (horní mez se hlásí).
- B6 doporučení kontroly a pravděpodobná příčina: u typů s generátorem ≥ 80 % zobrazených nálezů nese správný `catalog_id` (kontrola shody podle ground truth).

Odchylky od těchto prahů se zapíšou jako odchylka, ne jako splnění.

### Stav dodatku (průběžně)

| bod | stav |
|---|---|
| A plánovač mixů | hotovo: `--mix on`, 16 dvojic (4 x útok+útok, útok+porucha, útok+změna, porucha+porucha), vztah společná příčina / souběh / následek, `incident_id` v ground truth (`MixTag`), nástroj `tools/k13_mix.py` (A1 až A5); trojice nejsou. Zkušební běh 6 sítí OK (176 událostí, rovnoměrné dvojice). **Měření na ladicích seedech běží** (`k13mix`), držené zatím ne |
| B rešerše, studie 13 | hotovo ve smyslu poctivého omezení: `studie/13-katalog-provoznich-incidentu.md`; jen 2 zdroje (danluu, RFC 5227) skutečně načteny, ostatní `verified: false` |
| B katalog `data/incident-catalog.json` | hotovo: 75 typů (56 poruch, 15 neškodných změn, 4 nejednoznačné), modul `src/incident_catalog.rs` + test konzistence se simulátorem |
| B generátory | 51 z 75 typů má generátor (38 stávajících + 13 nových variant tvaru toků v `variants::SPECS`); 24 typů bez generátoru (rozlišené hlavně obsahem L2, DNS, syslog) |
| B klasifikace a doporučení v engine | **nezačato**: nález zatím nenese `catalog_id`, doporučení z katalogu v UI není; stávající třída provoz (`ops_class`, `ops_annotate`) byla v kroku 6 zamítnuta (útoky jen ve frontě provoz). B2, B3, B6 nejsou splněny ani změřeny; základní měření klasifikace složek mixů (A5) běží |

## Výsledky kroku 13 (průběžně zapisované)

### Bod 1: příčina chybějících logů Zeeku a kalibrace simulátoru

**Příčina u botnetů 42 a 54.** U 42 byla příčina kontrolní součty (checksum offload na zachycení): `zeek -C -r` je přeskočí a logy vznikly (59 413 DNS řádků, 63 TLS). U 54 logy ve skutečnosti vznikly dřív (15 447 DNS řádků, 370 TLS), ale zapsaly se do chybně pojmenovaného adresáře `out$n` (chyba shellu při běhu); přesunuto do `out/54`. Suricata ani vlastní parser nebyly potřeba.

**Pět zdrojů (Zeek, `tools/k13_real_stats.py`).**

| zdroj | DNS řádků | NXDOMAIN | TXT/NULL | AAAA | TLS | bez SNI | self-signed |
|---|---:|---:|---:|---:|---:|---:|---:|
| CTU-Normal-20 (normální Windows host, 3,1 h) | 15 089 | 0,013 % | 0 | 24,5 % | 2 464 | 1,5 % | 3,0 % |
| CTU-13 č. 42 (Neris) | 59 413 | 1,26 % | 0 | 0 | 63 | 88,9 % | 0 |
| CTU-13 č. 43 (Neris) | 1 005 | 0 | 0 | 0 | 43 | 97,7 % | 5,6 % |
| CTU-13 č. 46 (fast-flux) | 163 | 2,0 % | 0 | 0 | 72 | 100 % | 0 |
| CTU-13 č. 54 (fast-flux) | 15 447 | 1,69 % | 0 | 0 | 370 | 100 % | 0 |

**Omezení kalibrace (H1).** Všechny zdroje jsou virtuální stroje jedné laboratoře (ČVUT), dohromady jeden normální a čtyři infikované hosty z roku 2011, takže podmínka „min. 3 nezávislé zdroje na veličinu“ **není splněna**: všechny níže uvedené hodnoty jsou jen **orientační**. Botnet hosté nemají AAAA ani moderní TLS (rok 2011), proto AAAA a podíl bez SNI se berou jen z normálního hosta.

**Změny pozadí simulátoru (`--l7 cal`, `soak/l7sim.rs`):** NXDOMAIN 5 % na 1 % (rozpětí zdrojů 0,01 až 2 %); TXT z pošty 2 % na 0,5 % (všechny zdroje 0 %, tedy mimo ±2×, jen minimum pro mailové hosty); AAAA 20 % dotazů (normální host 24,5 %); dlouhá hashovaná jména 4 % beze změny (4,1 %); bez SNI 1,5 % a self-signed 3,0 % cílů (podle cíle, ne podle spojení; viz níže); neškodné změny míří na dosud neviděné jméno ve 13,4 % spojení (CTU-Normal-20). Mladé certifikáty (< 30 dní) se **nekalibrovaly** (čas zachycení nesedí s datem certifikátu, 100 % mladých je artefakt). Nepokryté veličiny: JA4 hostů, struktura cílů TLS, DNS útoku.

**Chyba nalezená při kalibraci (poučení).** První verze přiřazovala self-signed a bez SNI náhodně každému spojení; skupina spojení na jeden cíl pak skoro jistě obsahovala self-signed spojení a detektor `tls_novel_burst` vyráběl falešné poplachy (hn_mail_newsletter_burst zobrazeno 5 % → 34 %, FP poměr 1,156). Self-signed je ale vlastnost cíle (serveru), ne spojení. Po opravě (rozhoduje hash cíle) FP poměr 1,120 a hn_* +0,8 p. b. Běhy s chybnou verzí (`c2-*`) se nepoužívají.

**Kandidát v kalibrovaném světě (seed 20261102, 40 sítí, jeden seed, orientačně; matice viz protokol):** zobrazené FP na síť-den 7,52 → 8,42 (poměr 1,120, 1,050 až 1,201), detekce bezpečnostních útoků 84,8 → 87,7 % (+2,9 p. b.; +2,1 až +4,0), omylem zavřené 1,2 % → 0 %. Starý (nekalibrovaný) svět dával FP poměr 1,056 až 1,067: kalibrace přidala neškodná metadata, která FP zvyšují, ale pod prahem 1,15.

### Bod 2: reálné přehrání pcap -> Zeek -> Salticus (H4)

Nástroj `tools/k13_replay_zeek.py` (okna 1 800 s, logy conn, dns, ssl, x509, produkční cesta `beh spust`, bez inventáře, cold start). Škodlivý host = infikovaný 147.32.84.165 (CTU-13), neškodný host 10.0.2.15 (Normal-20). Hodnotí se na úrovni hostů.

| zdroj | oken | toků | zobrazených nálezů o škodlivém hostu (první okno) | o jiných hostech | rozdíl s L7 přepínači (`l7_tls`, `l7_dns`, `icmp_payload`) |
|---|---:|---:|---|---:|---|
| CTU-13 č. 42 | 10 | 31 735 | 11 (okno 0) | 0 | žádný |
| CTU-13 č. 43 | 7 | 40 198 | 9 (okno 0) | 5 (1 host) | žádný |
| CTU-13 č. 46 | 1 | 1 549 | 3 (okno 0) | 0 | žádný |
| CTU-13 č. 54 | 33 | 88 048 | 17 (okno 0) | 0 | žádný |
| Normal-20 (neškodný host) | 7 | 18 892 | 47 nálezů na neškodném hostu (FP, cold start) | 0 | žádný |

Čtení: všechny čtyři infikované hosty se zobrazí v prvním okně z tokových nálezů (pasivní událost bez inventáře, interaktivní relace, pravidelné volání, dlouhé spojení). **L7 detektory na těchto zachyceních nezasáhly ani u botnetů**: vyžadují zralého hosta (`mature_s`) a nový cíl s druhým rysem a objemem či dávkou; krátká zachycení (1 až 16 h) a malé objemy to nesplní, takže přínos L7 na reálných datech **nelze potvrdit ani vyvrátit**. Normální host dává 47 zobrazených nálezů za 3,1 h (hlavně „interaktivní relace“ k HTTPS cílům a pasivní události bez inventáře); je to cold-start měření s prázdným inventářem, ne provozní odhad. Rozdíl proti simulaci: simulace hlásí FP v jednotkách na síť-den, reálný neškodný host desítky za 3 h bez inventáře; srovnání je jen kvalitativní (H4).

**DoH a DNS tunel (bez formulářů).** Zenodo DoH datasety (Jeřábek a kol., záznamy 5956044, 5957278, 5957122, 5957466, 5957421, 5957660, 5957677) mají licenci CC-BY 4.0, ale 12 až 46 GB na soubor. Z `DoH-Real-World` (12,8 GB) jsem stáhl začátek (300 MB komprimovaně, 2,2 GB pcapng): zachycení je od prostředku spojení (`data_before_established`, `possible_split_routing`), Zeek vydal jen `conn.log` (65 534 TCP spojení) bez `ssl.log`, takže z něj nejsou metadata TLS ani SNI. **Slepé místo:** DoH (SNI na resolvery, tvar provozu) a DNS tunel zůstávají bez reálných dat. Repozitáře s pcapy DNS tunelů (Utah1A, ggyggy666) nemají licenci (GitHub API `license: null`), proto nestaženy. Doporučení: DoH z `DoH-Real-World` zpracovat celé a hlásit jen toky; DNS tunel z veřejného zdroje s ověřenou licencí (např. CIC-Bell-DNS2021 po souhlasu uživatele s registrací) nebo vlastní iodine a dnscat2 v laboratoři.

### Bod 3: seskupení incidentů (H2), ladicí seed 20261102 (40 sítí)

Metrika čistoty jako dosud (nález bez připsání = vlastní štítek). Úplnost = podíl dvojic nálezů téže pravdy ve stejném incidentu (offline z exportu, `tools/k13_incidents.py`; export je omezen na 20 000 událostí na síť, proto se čísla mírně liší od vestavěných).

| seskupení | čistota | nálezů na incident | podíl nálezů v incidentech >= 2 | úplnost |
|---|---:|---:|---:|---:|
| stávající, odstup 6 h | 37,5 % | 15,4 | neměřeno | neměřeno |
| stávající, odstup 1 h | 54,0 % | 7,9 | 80 % | 32 % |
| stávající, odstup 30 min | 55,3 % | 7,4 | 71 % | 26 % |
| `incident_v2` (stejný cíl a protějšek, nebo stejný cíl a typ nálezu), 1 h | **84,3 %** | 2,65 | 44 % | **2,5 %** |
| `incident_v2`, 30 min | 79,6 % | 2,78 | 26 % | 2,1 % |

**Příčiny nízké čistoty.** (1) Sdílené hosty: nález nese jako `host_key` cíl; server nebo resolver dostává útoky a poruchy od různých zdrojů, takže tranzitivní spojování „stejný host nebo indikátor“ slévá nesouvisející nálezy. Omezení hub-hostů čistotu zvedlo (88 % při limitu 3), ale úplnost spadla pod 3 %. (2) Šum: asi 31 % nálezů nemá připsanou pravdu a každý se počítá jako vlastní štítek, takže skupina šumu o 3 nálezech má čistotu 1/3 bez ohledu na seskupení. (3) Opakování téhož nálezu v čase se v metrice počítá jako několik nálezů; dedup podle `finding_id` čistotu nezlepšil.

**Verdikt H2.** Číselný práh (čistota >= 80 % na ladicím seedu, >= 2 nálezy na incident) `incident_v2` splňuje (84,3 %; 2,65), **ale zlepšení vzniklo roztříštěním**: úplnost spadla z 32 % na 2,5 % a v incidentech zůstalo 44 % nálezů místo 80 %. Takový incident je spíš shluk téhož hosta a téhož protějšku než celý příběh útoku. Cíl 90 % **není splněn**; držená část (>= 70 % na držených seedech) **nebyla změřena** (držené seedy se pouští až na konci). Žádná z vyzkoušených variant (hub limit, typ nálezu, dvojice host+protějšek, kombinace) nedala čistotu >= 80 % při úplnosti nad ~15 %; samotné rysy host, protějšek, typ a čas k lepšímu seskupení zřejmě nestačí a je potřeba vazba příčiny (závislosti služeb, `common_cause`), kterou simulace zatím nese jen u řízených mixů (dodatek A). `incident_v2` je v `retro::History::incidents_v2` (měření v soaku pod štítky `v2-1h`, `v2-30m`), **do produkční cesty (`correlation_layer`) není zapojen** a nedoporučuje se zapnout.

### Ladicí matice k13m (vyhodnoceno 2026-11-15, `tools/k13_matrix.py`)

Základ a kandidát (`breadth, bulk_clear, strict_close, l7_tls, l7_dns, icmp_payload`), 10 ladicích seedů, **92 párových sítí na rameno** (20 + 9 x 8; 0 nepárových), kalibrovaný svět (`--l7 cal`). Plná tabulka rodin je v `F:\work-tmp\k13\matrix-tune.md`; níže celek, konfigurace, rozptyl mezi seedy a rodiny se změnou.

### Celkem a po konfiguracích

| skupina (sítí) | ukazatel | základ | kandidát | rozdíl |
|---|---|---:|---:|---|
| vše (92) | zobrazené FP na síť-den | 13,37 | 15,33 | poměr 1,146 (1,053 až 1,220) |
| vše (92) | detekce bezpečnostních útoků | 84,9 | 87,2 | rozdíl +2,3 (+1,9 až +2,9) p. b. |
| vše (92) | hn_* zobrazeno (FP z pohledu útoku) | 61,8 | 62,5 | rozdíl +0,7 (+0,2 až +1,2) p. b. |
| vše (92) | útoky s omylem zavřeným | 0,8 | 0,0 | rozdíl -0,8 (-1,1 až -0,5) p. b. |
| small (38) | zobrazené FP na síť-den | 3,45 | 3,73 | poměr 1,080 (1,035 až 1,131) |
| small (38) | detekce bezpečnostních útoků | 83,8 | 86,7 | rozdíl +2,9 (+2,0 až +3,9) p. b. |
| small (38) | hn_* zobrazeno (FP z pohledu útoku) | 59,2 | 60,0 | rozdíl +0,8 (-0,4 až +1,9) p. b. |
| small (38) | útoky s omylem zavřeným | 0,9 | 0,0 | rozdíl -0,9 (-1,6 až -0,2) p. b. |
| medium (34) | zobrazené FP na síť-den | 26,13 | 26,06 | poměr 0,997 (0,966 až 1,022) |
| medium (34) | detekce bezpečnostních útoků | 81,1 | 84,0 | rozdíl +2,9 (+2,1 až +3,9) p. b. |
| medium (34) | hn_* zobrazeno (FP z pohledu útoku) | 63,5 | 63,7 | rozdíl +0,2 (-0,3 až +0,9) p. b. |
| medium (34) | útoky s omylem zavřeným | 0,7 | 0,0 | rozdíl -0,7 (-1,1 až -0,4) p. b. |
| large (20) | zobrazené FP na síť-den | 17,68 | 22,33 | poměr 1,263 (1,117 až 1,341) |
| large (20) | detekce bezpečnostních útoků | 89,1 | 90,6 | rozdíl +1,5 (+0,9 až +2,3) p. b. |
| large (20) | hn_* zobrazeno (FP z pohledu útoku) | 63,4 | 64,4 | rozdíl +1,1 (+0,3 až +1,9) p. b. |
| large (20) | útoky s omylem zavřeným | 0,8 | 0,1 | rozdíl -0,8 (-1,2 až -0,3) p. b. |
| XXL a větší (1) | zobrazené FP na síť-den | 119,00 | 122,00 | poměr 1,025 (1,025 až 1,025) |
| XXL a větší (1) | detekce bezpečnostních útoků | 76,0 | 80,0 | rozdíl +4,0 (+4,0 až +4,0) p. b. |
| XXL a větší (1) | hn_* zobrazeno (FP z pohledu útoku) | 0,0 | 0,0 | rozdíl +0,0 (+0,0 až +0,0) p. b. |
| XXL a větší (1) | útoky s omylem zavřeným | 0,0 | 0,0 | rozdíl +0,0 (+0,0 až +0,0) p. b. |

### Rozptyl mezi seedy (detekce bezpečnostních útoků a FP na síť-den, kandidát minus základ)

| seed | sítí | detekce základ | detekce kandidát | FP základ | FP kandidát |
|---|---:|---:|---:|---:|---:|
| 20261102 | 20 | 82,8 | 85,1 | 16,69 | 17,88 |
| 20261103 | 8 | 89,4 | 92,2 | 13,26 | 13,77 |
| 20266101 | 8 | 75,2 | 77,0 | 20,23 | 20,31 |
| 20266102 | 8 | 82,1 | 86,5 | 23,36 | 20,64 |
| 20266103 | 8 | 87,6 | 88,8 | 6,13 | 6,59 |
| 20266104 | 8 | 87,6 | 90,3 | 6,65 | 8,25 |
| 20266105 | 8 | 87,0 | 88,6 | 6,11 | 6,25 |
| 20266106 | 8 | 87,8 | 90,4 | 20,93 | 28,01 |
| 20266107 | 8 | 85,7 | 88,5 | 12,52 | 15,10 |
| 20266108 | 8 | 78,1 | 80,0 | 23,88 | 24,33 |

Rozdíl detekce po seedech: min +1,3, max +4,4 p. b. (seedů se zlepšením 10 z 10).

### Rodiny se změnou (n = útoků s toky v obou ramenech; rodiny beze změny vynechány)

| rodina | kategorie | n | základ | kandidát | rozdíl p. b. (95 %) |
|---|---|---:|---:|---:|---|
| backup_service_probing | security | 34 | 76,5 | 73,5 | -2,9 (-7,7 až +0,0) |
| broadcast_storm_loop | ops_fault | 25 | 4,0 | 24,0 | +20,0 (+4,3 až +34,5) |
| bucket_mass_download | security | 38 | 7,9 | 47,4 | +39,5 (+23,9 až +55,0) |
| c2_beacon | security | 264 | 85,6 | 87,1 | +1,5 (+0,3 až +3,0) |
| c2_cloud_storage_dead_drop | security | 31 | 48,4 | 51,6 | +3,2 (+0,0 až +10,3) |
| c2_dns_txt_beacon | security | 36 | 55,6 | 77,8 | +22,2 (+8,1 až +35,6) |
| c2_udp_custom_port | security | 36 | 91,7 | 94,4 | +2,8 (+0,0 až +8,8) |
| clicks_to_rare_destination | security | 26 | 11,5 | 15,4 | +3,8 (+0,0 až +12,0) |
| cloud_api_discovery_burst | security | 27 | 0,0 | 29,6 | +29,6 (+16,1 až +44,0) |
| cryptomining | security | 125 | 89,6 | 90,4 | +0,8 (+0,0 až +2,4) |
| ddos_dns_amplification | security | 25 | 60,0 | 80,0 | +20,0 (+8,3 až +34,8) |
| dhcp_pool_exhaustion | ops_fault | 26 | 7,7 | 11,5 | +3,8 (-5,9 až +15,0) |
| dns_slow_resolution | ops_fault | 33 | 63,6 | 66,7 | +3,0 (+0,0 až +8,6) |
| dns_tunnel | security | 124 | 91,9 | 94,4 | +2,4 (+0,0 až +5,3) |
| dns_zone_enum_burst | security | 32 | 15,6 | 46,9 | +31,2 (+14,3 až +48,6) |
| drive_by_bulk_download | security | 33 | 9,1 | 48,5 | +39,4 (+25,0 až +55,6) |
| exfil_alt_protocol_ftp | security | 23 | 13,0 | 65,2 | +52,2 (+36,8 až +68,8) |
| exfil_cloud_storage_upload | security | 31 | 41,9 | 51,6 | +9,7 (+0,0 až +19,4) |
| exfil_dns_slow | security | 36 | 80,6 | 94,4 | +13,9 (+2,6 až +27,8) |
| exfil_https_burst | security | 32 | 50,0 | 56,2 | +6,2 (+0,0 až +14,3) |
| exfil_icmp_payload | security | 35 | 51,4 | 94,3 | +42,9 (+30,0 až +56,7) |
| exfil_over_c2_trickle | security | 20 | 50,0 | 65,0 | +15,0 (+0,0 až +31,2) |
| exfiltration | security | 196 | 88,3 | 88,8 | +0,5 (+0,0 až +1,5) |
| fleet_beacon | security | 44 | 93,2 | 95,5 | +2,3 (+0,0 až +6,5) |
| hn_admin_bulk_ssh | benign_change | 170 | 80,0 | 81,2 | +1,2 (+0,0 až +2,6) |
| hn_cdn_update_download | benign_change | 183 | 10,9 | 13,1 | +2,2 (+0,6 až +3,9) |
| hn_db_replication_bulk | benign_change | 167 | 80,8 | 79,6 | -1,2 (-3,9 až +1,3) |
| hn_monitoring_snmp_sweep | benign_change | 154 | 77,3 | 77,9 | +0,6 (+0,0 až +2,0) |
| hn_nightly_cloud_backup_upload | benign_change | 158 | 56,3 | 58,9 | +2,5 (+0,7 až +4,4) |
| insider_after_hours_cloud_sync | security | 31 | 51,6 | 71,0 | +19,4 (+8,1 až +33,3) |
| lateral_wmi_dcom | security | 47 | 97,9 | 100,0 | +2,1 (+0,0 až +5,7) |
| mail_forward_smtp_exfil | security | 35 | 57,1 | 77,1 | +20,0 (+9,4 až +31,4) |
| mdns_ssdp_storm | ops_fault | 26 | 11,5 | 38,5 | +26,9 (+11,5 až +45,0) |
| ntlm_relay_style_fanout | security | 36 | 94,4 | 97,2 | +2,8 (+0,0 až +8,0) |
| ntp_unreachable | ops_fault | 32 | 50,0 | 43,8 | -6,2 (-12,9 až +0,0) |
| planned_patch_reboot_wave | benign_change | 34 | 100,0 | 97,1 | -2,9 (-7,1 až +0,0) |
| share_encryption_wave_slow | security | 23 | 91,3 | 95,7 | +4,3 (+0,0 až +13,0) |
| smb_sweep_ext | security | 30 | 80,0 | 83,3 | +3,3 (+0,0 až +9,4) |
| telnet_iot_login | security | 37 | 59,5 | 62,2 | +2,7 (+0,0 až +8,6) |

**Rozhodnutí o kandidátu podle předregistrovaných prahů (H3).**

| stráž | výsledek | verdikt |
|---|---|---|
| omylem zavřené = 0 | základ 0,8 % -> kandidát 0,0 % (malé a medium 0,0; large 0,1 % = 1 případ) | splněno celkově; horní mez Wilson viz níže, v large zbytek 0,1 % |
| FP poměr <= 1,15 | celkem 1,146 (1,053 až 1,220), small 1,080, medium 0,997, **large 1,263 (1,117 až 1,341)** | celkem těsně splněno (bod), horní mez 95 % nad prahem; **large překračuje** |
| hn_* zobrazeno | +0,7 p. b. celkem (+0,2 až +1,2), large +1,1 | malý nárůst, v pásmu; držené se hlásí zvlášť |
| detekce | +2,3 p. b. (+1,9 až +2,9), všech 10 seedů se zlepšením (min +1,3, max +4,4) | zlepšení potvrzeno |

Rozhodnutí: **kandidát se ponechává jako kandidát na držené seedy, s odchylkou.** Práh FP je splněn jen bodově a v konfiguraci large (20 sítí) není: ladicí matice neumí z jediného kandidáta říct, který detektor FP v large tvoří (LOFO běží až po rozhodnutí). Důvod pro ponechání: práh je předregistrován jako celkový poměr, ne po konfiguracích; opak by byl dodatečné zpřísnění po pohledu na data. Odchylka se zapisuje jako **odchylka, ne splnění**: FP poměr v large 1,263 > 1,15. Co se stane: LOFO (`l7_tls`, `l7_dns`, `icmp_payload`) ukáže, který detektor FP v large způsobuje; ten se do držené sady nepouští zapnutý, pokud LOFO potvrdí příčinu a odečtená detekce zůstane nad základem. Na držených seedech se kandidát hodnotí jednou, beze změn po ladění.

Rodiny: největší zisky u exfil_alt_protocol_ftp (+52), exfil_icmp_payload (+43), bucket_mass_download (+39), drive_by_bulk_download (+39), dns_zone_enum_burst (+31), cloud_api_discovery_burst (+30), mdns_ssdp_storm (+27), c2_dns_txt_beacon (+22). Zhoršení pod šumem: ntp_unreachable -6,2 (-12,9 až 0,0), backup_service_probing -2,9, planned_patch_reboot_wave -2,9, hn_db_replication_bulk -1,2 (všechny intervaly obsahují 0). Rodiny pod 50 % po kandidátu (vstup pro bod 4): clicks_to_rare_destination 15, dhcp_pool_exhaustion 12, hn_cdn_update_download 13 a hn_mail_newsletter_burst 8 (to jsou neškodné, tam je nízká hodnota žádoucí), broadcast_storm_loop 24, mdns_ssdp_storm 39, cloud_api_discovery_burst 30, ntp_unreachable 44, bucket_mass_download 47, drive_by_bulk_download 49, dns_zone_enum_burst 47.

### Rozšíření ladicí matice (spuštěno 2026-11-15)

Limit „max 6 vláken“ zrušen (až 16 souhrnně, Idle, maska jader 0x3FFFFC). Do `soak run` přibyl přepínač `--block-offset` (další sítě téhož seedu; `network_id = (blok + offset) * block_size + k`), takže rozšíření nemíchá sítě z původní matice. Determinismus ověřen: seed 20261103, sítě 0 a 1, offset 0 novou binárkou (`k13d.exe`) dává stejné řádky `networks.jsonl` jako původní běh, liší se jen časové údaje (`wall_s`, `cycle_p99_s`).

Běh `runs6.ps1` (`F:\work-tmp\k13`, výstup `F:\Projektyakula-soak\k13m2`): dvě ramena (base, cand) paralelně po 5 vláknech vedle `runs4.ps1` (6 vláken, mixy) = 16 vláken. Pro každý ladicí seed +16 sítí (seed 20261102 od sítě 20, ostatní od sítě 8), tj. plánovaně +160 sítí na rameno, celkem 252 na rameno po dokončení. **Skutečný dosažený počet bude zapsán po dokončení**; cíl 600 až 1 000 není dosažen (odhad času a další rozšíření podle rychlosti po prvních seedech).

### Sloučená ladicí matice k13m + k13m2 (2026-11-15)

Doběhla obě ramena. **Skutečný počet: 252 párových sítí na rameno** (92 + 160, 0 nepárových, 10 seedů, 30 buněk seed x konfigurace), nikoli cílových 600 až 1 000; důvod je čas běhu (kalibrovaný svět, největší sítě stovky zařízení). Plná tabulka: `F:\work-tmp\k13\matrix-merged.md`.

| skupina (sítí) | ukazatel | základ | kandidát | rozdíl |
|---|---|---:|---:|---|
| vše (252) | zobrazené FP na síť-den | 10,70 | 12,02 | poměr 1,123 (1,082 až 1,167) |
| vše (252) | detekce bezpečnostních útoků | 85,4 | 88,2 | +2,8 p. b. (+2,4 až +3,2), 10 seedů z 10 se zlepšením (min +1,8, max +3,5) |
| vše (252) | hn_* zobrazeno | 62,6 | 63,5 | +0,9 (+0,5 až +1,2) |
| vše (252) | útoky s omylem zavřeným | 0,7 | 0,0 | -0,7 (-0,9 až -0,5) |
| small (123) | FP na síť-den | 4,66 | 5,13 | 1,100 (1,078 až 1,121) |
| medium (78) | FP na síť-den | 20,29 | 20,95 | 1,033 (1,001 až 1,068) |
| large (51) | FP na síť-den | 20,08 | 23,75 | **1,182 (1,107 až 1,248)** |
| XXL a větší (8) | FP na síť-den | 85,12 | 95,21 | 1,118 (1,102 až 1,146) |

Se 252 sítěmi je celkový poměr FP 1,123, horní mez 1,167 je těsně nad 1,15. V large zůstává bodově nad prahem (1,182); dolní mez 1,107 je pod prahem, takže překročení není s jistotou prokázáno.

### Ladicí mixy k13mix (80 sítí, 1943 složek, `tools/k13_mix.py`)

Zobrazeno 77,6 % složek (75,7 až 79,4), omylem zavřeno 0, **správná kategorie (A5) 56,0 % (53,5 až 58,5), cíl 90 %: nesplněno**. Důvod: kategorie se dosud zjišťuje jen z provozní anotace (E1 až E3); neškodné změny a většina poruch bez evidence E1 až E3 skončí jako „bez provozní značky“. Detekce složky v mixu proti téže rodině mimo mix: společná příčina 0,951, souběh bez vazby 0,993, následek 1,168 (A1: složky se v mixu neztrácejí). Seskupení: původní (host nebo indikátor, 1 h) má čistotu 36,5 % (cíl 80 %: nesplněno) a 36,9 nálezu na incident; `incident_v2` (host+protějšek nebo host+typ) má čistotu 86,9 % (cíl splněn) a chybné spojení souběhu bez vazby 0 z 92 (cíl <= 15 % splněn), ale společná příčina a následek jsou rozdělené v 20 z 21 případů (95,2 %, cíl <= 30 % nesplněn). Výsledky: `F:\work-tmp\k13\mix-tune.md`.

### Příčina FP v konfiguraci large a oprava před držením seedů

Rozpis zobrazených FP podle typu nálezu (kandidát minus základ, 51 sítí large): `slow_egress` +2088 (0 -> 2088), `connection_timeout_burst` +197, `packet_rate_spike` +184, `unmapped_passive_event` +66, `broadcast_storm` +41, `tls_rare_transfer` +27 (l7_tls), ostatní jednotky. Detektory `l7_dns` a `icmp_payload` v zobrazených FP nefigurují vůbec (0 nálezů); `l7_tls` přidává v celé matici 94 `tls_rare_transfer` z celkových +3647 (2,6 %). **Převážná příčina (79 % nárůstu v large) je `slow_egress` z detektoru `breadth`**, soustředěný v sítích Cloud (1797 z 2088) a Datacenter (291): v sítích se stovkami hostů mnoho hostů odesílá pomalu na cíle sdílených služeb (SaaS, API, sklad), které nejsou „zvykem“ jednoho hosta. Tentýž detektor ale pomáhá detekci exfiltrace (v `cf_type_hits` exfil_scheduled_chunks 81, mail_forward_smtp_exfil 69, exfil_over_c2_trickle 57), proto se nevypíná celý.

Oprava (před držením seedů, přepínač `slow_fanin`): `slow_egress` se nehlásí pro cíl, na který v historii odesílalo víc než 6 různých zdrojů (služba sítě, ne pomalý únik jednoho hosta). Hodnota 6 je volba autora z mechanismu, ne ladění na měření; test `slow_egress_skips_destination_used_by_many_sources`. Možná ztráta: flotilové rodiny (`fleet_beacon`, `update_channel_compromise_fleet`) mohou tento typ ztratit, ostatní typy je zachytí. Měření oprav a LOFO (5 ladicích seedů, 16 sítí na seed, bloky k13m2): `F:\Projekty\bakula-soak\k13m3`, ramena `c2` (kandidát + `slow_fanin`), `no_tls`, `no_dns`, `no_icmp`; výsledek viz níže.

### Bod 4: rozbor příčin zbylých nedetekcí (bez ladění na testovací scénář)

Z kandidáta (252 sítí) u bezpečnostních útoků: 15 976 emitovaných, zobrazeno 14 437 (90,4 %), **nedetekováno 1086** (z toho 473 = 44 % ztráta telemetrie senzoru nebo žádné viditelné toky: mimo dosah detektorů) a **detekováno, ale nezobrazeno 453** (`state_open` 292, `suppressed` 83, `state_confirmed` 70: slití s dříve zobrazeným nálezem téhož klíče). Největší mezery detektorů: clicks_to_rare_destination 67, port_scan_vertical 64, exploit_attempt 60, c2_beacon 47, bucket_mass_download 46, cloud_api_discovery_burst 42, ssh_bruteforce 38. Skryté (slití): c2_beacon 31, port_scan_horizontal 28, exploit_attempt 27.

Závěr bodu 4: rozbor ukazuje tři příčiny a žádná se v tomto kroku neodstraní tak, aby rodiny dosáhly 100 %. (1) 44 % nedetekcí je ztráta telemetrie, kterou detektor nevyřeší. (2) Slití s otevřeným klíčem: `redisplay` a `redisplay_age` byly změřeny v kroku 12 a zamítnuty (FP x2,69); nové zapnutí bez nového mechanismu by opakovalo zamítnutý pokus. (3) Mezera detektoru u rodin bez vlastního signálu (clicks_to_rare_destination, port_scan_vertical): nový detektor by se ladil na testovací rodinu, proto se nepřidává a zapisuje se jako otevřená mezera. Detekce bezpečnostních útoků zůstává 88,2 % (kandidát); cíl „posun k 100 %“ **splněn není**.

### Katalog, generátory a trojice (2026-11-15)

- **Ověření zdrojů katalogu**: skript `F:\work-tmp\k13\verify_sources.py` načetl všech 36 URL; `verified: true` je nyní u 31 (stránka se skutečně načetla a odpovídá tvrzenému zdroji, titulek je v poli `verification`), `false` u 5 (ITIL/Axelos jen obecná úvodní stránka, IEEE 802.1D 404, Cisco, Aruba a NANOG 403). `verified` neznamená ověření každého tvrzení o projevu: ta zůstávají `basis: assumption`. Juniper se přesměrovává na portál HPE Networking, URL aktualizována.
- **Generátory**: přidáno 24 řádků do `SPECS` (`src/soak/variants.rs`); všech 75 typů katalogu má `sim_variant` (B1: 100 %, dříve 51 z 75 = 68 %). Čtyři nejednoznačné typy (VLAN hopping, rogue DHCP, rogue zařízení, DDoS vs flash crowd) se generují s příčinou poruchy a jako tvrdý záporný scénář (`hard`, jen svět k10). **Důsledek**: výběr variant v `plan_variants` losuje z `SPECS`, takže světy s poruchami (k9, k10) se po této změně liší od ladicích běhů před změnou; ladicí matice výše byla měřena starou tabulkou (51 poruch a změn), držené seedy novou. Čísla před a po proto nejsou párově srovnatelná po rodinách.
- **Trojice v mixech**: `MIX_TRIPLES` (8 trojic: následek x 3, společná příčina, souběh bez vazby x 3 s útokem, poruchou a neškodnou změnou); druhá a třetí událost začíná v okně první, štítek `pair = 100 + index`, `role` 0 až 2. `tools/k13_mix.py` je počítá po složkách (A1, A2, A5); A3 a A4 (seskupení) zůstávají jen u dvojic. Test `mix_tables_reference_existing_variants`.
- **Zařazení podle katalogu v enginu**: `incident_catalog::suggest` (nález bez provozního důkazu = `utok`, E2 = porucha OPS-013, E3 = změna CHG-001, E1 = porucha OPS-016); `LifecycleRecord.catalog` (třída, id, název, příčina, doporučená kontrola) vzniká u každého zobrazeného nálezu s `ops_annotate` a jde do reportu (`finding_lifecycle`). Měření v soaku: `attacks[].catalog`, nástroj `tools/k13_catalog.py` (B2, B3, B6). Mapování je záměrně hrubé (typ nálezu + důvod fronty provoz); B2 a B6 se měří, ne předpokládají.

| bod | stav |
|---|---|
| ladicí matice k13m + k13m2 (252 sítí/rameno) | vyhodnoceno |
| ladicí mixy k13mix | vyhodnoceno, A5 56 % (nesplněno) |
| příčina FP v large | `slow_egress` (breadth); oprava `slow_fanin` v kódu, měření běží (k13m3) |
| bod 4 | rozbor hotov, bez změny detektorů (důvody výše) |
| katalog: verified, 24 generátorů, trojice, `catalog_id` v enginu | hotovo v kódu; UI, testy, B2/B3/B6 měření: viz níže |
| držené seedy a souhrn | hotovo, viz sekce na konci |

## Držené seedy, LOFO a souhrn (2026-11-15)

Kandidát `final` = `breadth,bulk_clear,strict_close,l7_tls,l7_dns,icmp_payload,slow_fanin,ops_annotate` (binárka k13f). Držené seedy 20265101 až 20265502, 8 sítí na seed, 80 sítí na rameno, párově (`base` x `final`), spuštěno jednou, bez úprav po pohledu na výsledek. Surové tabulky: `F:\work-tmp\k13\matrix-held.md`, `mix-held.md`, `catalog-held.md`.

### LOFO na ladicích seedech (k13m3, 5 seedů, 80 sítí, `c2` = celý kandidát)

| odebraný prvek | detekce | FP na síť-den | omylem zavřené |
|---|---|---|---|
| `l7_tls` | -0,8 p. b. (-1,0 až -0,5) | poměr 0,996 | 0 |
| `l7_dns` | -0,6 p. b. (-0,9 až -0,4) | 0,999 | 0 |
| `icmp_payload` | -0,3 p. b. (-0,4 až -0,1) | 1,000 | 0 |

Každý ze tří prvků detekci zvyšuje a FP nezvyšuje, proto zůstávají všechny. Ostatní prvky (`breadth`, `bulk_clear`, `strict_close`, `slow_fanin`, `ops_annotate`) mají zatím jen společné měření, LOFO pro ně neproběhlo.

### Matice, držené seedy (H3 a B5)

| ukazatel | základ | kandidát | rozdíl |
|---|---:|---:|---|
| zobrazené FP na síť-den (poměr součtů) | 12,04 | 12,73 | **poměr 1,058 (1,026 až 1,077)**, práh 1,15 splněn i horní mezí |
| detekce bezpečnostních útoků | 83,9 | 86,9 | **+3,1 p. b. (+2,4 až +3,8)**, zlepšení u 10 z 10 seedů (min +0,9, max +5,1) |
| omylem zavřené útoky | 30 z 5475 (0,55 %) | **0 z 5475**, horní mez Wilson 95 % 0,07 % | splněno |
| hn_* zobrazeno (všech 8 hn rodin) | 62,8 | 64,4 | +1,6 p. b. (+0,5 až +2,6) |

Po konfiguracích (FP poměr / detekce): small 1,044 / +3,9; medium 1,079 / +3,0; large 1,027 / +2,0; XXL a větší 1,001 / +2,5. Odchylka z ladicí sady (large 1,263) se na držených seedech neopakuje (large 1,027); oprava `slow_fanin` tedy zabrala. Čtyři držené hn rodiny (zobrazeno z pohledu útoku, nižší je lepší): hn_nightly_cloud_backup_upload 50,7 -> 54,9; hn_db_replication_bulk 82,5 -> 82,5; hn_monitoring_snmp_sweep 89,7 -> 91,2; hn_password_sync_periodic 91,8 -> 91,8. Neškodné rodiny se tedy zobrazují o něco častěji (cena za detekci), nikdy méně.

Mix běhy (`--mix on`, 80 sítí, 8255 útoků): omylem zavřeno 0, horní mez 0,05 %.

### Detekce po rodinách a rodiny pod 100 %

Z 74 bezpečnostních rodin s n >= 20 je po kandidátu na 100 % jen 10, pod 100 % 64. Cíl „posun k 100 %“ **splněn není**: celková detekce 86,9 %. Největší zisky (základ -> kandidát): exfil_alt_protocol_ftp 5,0 -> 70,0; exfil_icmp_payload 52,5 -> 95,0; dns_zone_enum_burst 9,4 -> 59,4; drive_by_bulk_download 6,1 -> 51,5; bucket_mass_download 16,7 -> 50,0; ddos_dns_amplification 55 -> 85; exfil_https_burst 54,2 -> 79,2; cloud_api_discovery_burst 9,5 -> 28,6; exfil_cloud_storage_upload 10,7 -> 28,6; c2_dns_txt_beacon 57,1 -> 71,4. Zhoršení bez významnosti (interval obsahuje 0): http_slow_connections_dos 70,8 -> 62,5, snmp_sweep_ext 95 -> 90.

Nejníž zůstávají: clicks_to_rare_destination 9,4; cloud_api_discovery_burst 28,6; exfil_cloud_storage_upload 28,6; bucket_mass_download 50,0; drive_by_bulk_download 51,5; dns_zone_enum_burst 59,4; http_slow_connections_dos 62,5; c2_cloud_storage_dead_drop 65,2; telnet_iot_login 65,2; exfil_alt_protocol_ftp 70,0; smb_sweep_ext 70,0.

Důvody (rozbor bodu 4, nebylo laděno): (1) zhruba 44 % nedetekcí je ztráta telemetrie senzoru nebo žádné viditelné toky, mimo dosah detektorů; (2) nálezy detekované, ale nezobrazené (slití s dříve zobrazeným nálezem téhož klíče); jejich odstranění (`redisplay`) bylo v kroku 12 zamítnuto kvůli FP x2,69; (3) rodiny bez vlastního signálu (clicks_to_rare_destination, bucket, cloud-api, drive-by), kde by nový detektor byl ladění na testovací rodinu. U rodin s 65 až 70 % (c2_cloud_storage_dead_drop, telnet_iot_login, smb_sweep_ext) se příčina nezkoumala, zapsáno jako otevřená mezera, ne jako vysvětlení.

### Mixy (dodatek A), držené seedy

Nástroj `k13_mix.py` padal na trojicích (KeyError, očekával právě dvě role); opraveno tak, že A3 a A4 berou jen dvojice (role 0 a 1), A1, A2, A5 počítají i trojice.

| práh | výsledek | verdikt |
|---|---|---|
| A1 složka nejméně 90 % relativně k téže rodině samotné | agregovaně relativně 1,18 (společná příčina), 1,01 (souběh), 1,21 (následek); po složkách propady: exfil_https_burst -13,6 p. b., ddos_syn_flood_distributed -13,2 a -17,8, dns_partial_failure -19,8, switch_outage_subnet -10,5, broadcast_storm_loop (dvojice 104) -22,5 | splněno po agregaci, **po složkách ne** (několik složek pokles > 10 p. b., část při malém n samostatně) |
| A2 omylem zavřené = 0 | 0 z 2750 složek, zobrazeno 80,5 % (79,0 až 82,0) | splněno |
| A3 čistota >= 80 % a >= 2 nálezy na incident | původní seskupení 45,0 % (24,8 nálezu na incident, tj. mega-skupiny); `incident_v2` 88,9 %, 2,86 nálezu na incident | splněno pro v2 (H2 na držených >= 70 % také) |
| A4 chybné spojení <= 15 % | původní 21,2 %; v2 1,2 % | splněno pro v2 |
| A4 rozdělení společné příčiny <= 30 % | původní 64,5 %; v2 83,9 % (26 z 31) | **nesplněno**: v2 správně neslučuje souběh, ale společnou příčinu a následek rozděluje; čistota 88,9 % je zčásti dosažena roztříštěním |
| A5 správná kategorie >= 85 % (držené) | 54,0 % (51,9 až 56,0) | **nesplněno**. Útoky 74 až 100 %, poruchy a neškodné změny 0 až 30 % (např. hn_cdn_update_download 0,0, planned_maintenance_window 3,2, dns_partial_failure 29,0) |

### Katalog (dodatek B), mix běhy

| práh | výsledek | verdikt |
|---|---|---|
| B1 pokrytí | 75 typů, všech 75 s generátorem | splněno (dříve) |
| B2 správná kategorie >= 85 % | útok 97,5 % z 91 171 nálezů; porucha 5,0 % (21 530), neškodná změna 0,4 % (6 941), nejednoznačné 1,7 % (2 697) | **nesplněno u všeho kromě útoků** |
| B3 maskovaná porucha zařazená jako útok <= 10 % | poruchy a změny jsou zařazeny jako útok v 94,7 % a 96,8 % | **nesplněno** (opačný směr, útok maskovaný jako porucha, tento nástroj neměří) |
| B4 žádná porucha zavřená jen proto, že není útok | samostatně neměřeno; omylem zavřené = 0 platí pro útoky | nedoloženo |
| B5 FP <= 1,15 a omylem zavřené = 0 | 1,058; 0 (horní mez 0,07 %) | splněno |
| B6 správný catalog_id u typů s generátorem >= 80 % | 0,7 % z 31 168 nálezů (běh final 0,0 %) | **nesplněno** |

Příčina: `incident_catalog::suggest` dává `porucha` jen tehdy, když nález nese provozní důkaz (E1 až E3). Simulované poruchy ho nesou v asi 5 % případů, ostatní jdou jako `utok|-`. Mapování je dle zadání hrubé; výsledek ukazuje, že pro poruchy a změny nefunguje a UI údaj „pravděpodobná příčina“ by tam byl chybně útokový. Katalog proto zatím slouží jako dokumentace a pro útoky (97,5 %), ne jako klasifikátor provozních incidentů. Oprava vyžaduje další provozní důkazy v enginu (DHCP, ARP, SNMP, syslog) a je mimo tento krok.

### Determinismus

`soak verify --samples 5` na bloku kandidáta (k13f, běh final-20265101): 4/4 bloky bit po bitu shodné.

### Návrh `recommended()` (neprovedeno, ke schválení)

Návrh: přidat do `EngineConfig::recommended()` přepínače `breadth, bulk_clear, strict_close, l7_tls, l7_dns, icmp_payload, slow_fanin` a rozhodnout o `ops_annotate`. Důkaz pro celou měřenou sadu osmi: držené seedy, 80 sítí, detekce +3,1 p. b. (+2,4 až +3,8), 10 z 10 seedů; FP poměr 1,058 (horní mez 1,077 < 1,15); omylem zavřené 0 z 5475 (horní mez 0,07 %), základ 0,55 %; LOFO potvrzuje l7_tls, l7_dns, icmp_payload. Výhrady: (a) `ops_annotate` nemá doložený přínos pro detekci a jeho klasifikace nesplnila B2 ani B6; (b) LOFO pro `breadth`, `bulk_clear`, `strict_close`, `slow_fanin` neproběhlo, příspěvek je změřen jen společně. Přesně měřená varianta je všech osm přepínačů; sedm bez `ops_annotate` je neměřená kombinace a před přijetím vyžaduje jeden párový běh na ladicích seedech. Do kódu se nic nemění, dokud to uživatel neschválí.

## Souhrn kroku 13 podle předregistrace

| práh | verdikt |
|---|---|
| H1 kalibrace | částečně (bod 1; nepokryté veličiny zapsány jako nekalibrované) |
| H2 čistota seskupení >= 80 % ladicí, >= 70 % držené | splněno (88,9 % na držených mixech); cíl 90 % ze zadání ne |
| H3 stráže (0 zavřených, FP <= 1,15, hn_* zvlášť) | splněno na držených; ladicí large 1,263 opraveno (držené 1,027) |
| H4 reálné přehrání | splněno kvalitativně (bod 2) |
| posun k 100 % | **nesplněno** (86,9 %, 64 z 74 rodin pod 100 %) |
| A1 (agregát), A2, A3, A4 (spojení) | splněno (A1 po složkách s propady) |
| A4 rozdělení, A5 | **nesplněno** (83,9 % a 54,0 %) |
| B1, B5 | splněno |
| B2, B3, B6 | **nesplněno** (poruchy 5 %, catalog_id 0,7 %) |
| B4 | nedoloženo |
