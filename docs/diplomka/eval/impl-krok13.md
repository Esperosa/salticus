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
- **Rozsah ladicí sady (plán):** 20261102 a 20261103 po 40 sítích, osm dalších seedů po 20 sítích = 240 sítí na rameno. Držená sada: 10 seedů po 20 sítích = 200 sítí na rameno (po částech).
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
| A plánovač mixů | nezačato (předregistrováno) |
| B rešerše, studie 13 | nezačato |
| B katalog `data/incident-catalog.json` | nezačato |
| B generátory pro typy bez variant v `variants::SPECS` | nezačato |
| B klasifikace a doporučení v engine | nezačato |
