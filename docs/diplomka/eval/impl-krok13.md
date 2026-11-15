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
| 4 posun k 100 % | nezačato |
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
- **Pořadí běhů (skripty v `F:\claude-tmp\k13
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
