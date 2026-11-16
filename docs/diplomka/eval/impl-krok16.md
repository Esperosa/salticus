# Krok 16: případová složka pro seniora jako hlavní produkt

Datum zahájení 2026-11-16. Výchozí stav: konec kroku 15 (commit `dcda412`). Závazný rozsah: `docs/diplomka/rozsah-autonomie.md` (oddíl „Hlavní výstup: případová složka“). Zadání: `F:\claude-tmp\briefs\krok16-pripadova-slozka.txt`. Tento krok nemění detekci ani prahy; měří se kvalita a úplnost výstupu.

## Co dnes dělá přepínač `case_files` (krok 12)

`case_files` (v `recommended()` vypnut) v pipeline v3 po žebříku volá `correlation_layer::run`: zapíše nálezy do historie incidentů (`retro`), rozhodnutí do účetní knihy (`reassess`) a **jen pro eskalované případy** sestaví `case_file::CaseFile` (časová osa ze dvou bodů: otevřeno a předáno; ověřené a neověřené kontroly; posterior z `competing::assess`, ne z verdiktu žebříku; proč nerozhodnuto; co by rozhodlo; žádosti o chybějící data). Strop 200 spisů na report. Chybí: shrnutí a doporučený krok, aktéři, důkazy pro a proti s původem a nezávislostí, typovaná nejistota, cena a riziko zbývajících kontrol, důvod předání podle pravidel rozsahu, odkaz na incident, složka pro zavřené (L1) a potvrzené případy. Posterior spisu se může lišit od verdiktu enginu (jiné tabulky věrohodnosti), což je nekonzistence, kterou tento krok odstraňuje.

## Návrh

Nový modul `case_folder.rs` (čistá funkce, bez I/O, bez času, bez náhody) a přepínač `case_folder` (výchozí vypnuto, vyžaduje `case_files`). Vstupem je rozhodnutí žebříku (nově s kroky včetně poměru věrohodnosti a textu, `verify_ladder::StepNote`; rozhodování se nemění), nález, záznam životního cyklu (diagnóza provozu, katalog), stav pokrytí, záznamy kontextu (vlastník a expirace) a incidenty z historie. Výstup `CaseFolder` (schéma `salticus.case_folder/1`) v `report.correlation.caseFolders` a čitelně přes `/runs/{id}/export/cases-txt` a `cases-html` (bez změny UI).

Povinná pole (každé vyplněné, nebo výslovně „nelze určit, chybí X“): shrnutí jednou větou, doporučený krok, verdikt (stav, úroveň L1/L2/L3, P(útok) přesně z verdiktu enginu), časová osa, aktéři (host, uživatel, proces, spojení, protějšek; uživatel jen pseudonym, je-li tak nastaveno), hypotézy s pořadím a typovanou nejistotou (každý typ hodnota, nebo „nelze určit“ se zdůvodněním), důkazy PRO a PROTI (původ: síť, L7, endpoint, provoz, kontext, vnější znalost, aktivní kontrola; skupina nezávislosti; poměr věrohodnosti; zda nese plnou váhu), ověřeno (úroveň žebříku, výsledek), zbývá ověřit (cena, nutnost schválení, riziko), slepá místa a žádosti o data, souvislosti (incident, související nálezy), důvod předání člověku (chráněný prostředek, chybí pozitivní důkaz, konflikt hypotéz, vysoký dopad, vyčerpaný rozpočet, slepé místo, potvrzené podezření čeká na rozhodnutí o zásahu). Zavřené případy (L1) nesou důkaz neškodnosti, kterým byly zavřeny, vlastníka a expiraci (nebo „nelze určit“ s důvodem, a to se počítá jako mezera).

Složka nic nerozhoduje a nic nespouští. Typovaná nejistota: `observation` = podíl provedených kontrol bez výsledku (měřeno z kroků), `interpretation` = rozdíl dvou nejpravděpodobnějších hypotéz, `identity` = stav přiřazení hosta (kategorie, bez čísla), `aleatoric` a `epistemic` = „nelze určit“ (z jednoho případu je nelze odhadnout; tabulky věrohodnosti jsou ze simulace). Rozdělení pravděpodobnosti mezi neškodné hypotézy je rovnoměrné, dokud ho neodliší důkaz, a složka to výslovně uvádí.

## Předregistrace (zapsáno před implementací měření)

Žádné ladění prahů ani detekce; přepínač nemění rozhodnutí. Validátor `case_folder::validate` je součást kódu a stejná pravidla počítá i skript měření (`tools/k16_case_folders.py`) nad dumpem složek.

| práh | metrika | splněno, když |
|---|---|---|
| K16-1 | úplnost: každé povinné pole vyplněno nebo výslovně „nelze určit“ | 100 % složek (simulace i reálná data) |
| K16-2 | pokrytí: žádný případ předaný člověku (eskalováno, potvrzeno) ani zavřený žebříkem bez složky; v pipeline i otevřené zobrazené nálezy | 100 %; složky zahozené kvůli stropu = 0 (jinak se hlásí počet) |
| K16-3 | konzistence s verdiktem: stav, P(útok), úroveň, uzávěr jen u vyvrácených, důvod předání jen u předaných | 100 % |
| K16-4 | složka netvrdí víc než důkazy: každý důkaz odpovídá provedenému kroku s výsledkem; důkaz PRO jen z podezřelého výsledku, PROTI jen z neškodného; zavřená složka má aspoň jeden silný neškodný důkaz; shrnutí eskalovaného případu netvrdí „útok“ ani „neškodné“; žádná vymyšlená hodnota (pravděpodobnosti konečné v [0, 1], chybějící = „nelze určit“) | 0 porušení |
| K16-5 | stabilita schématu: verze, pevná množina klíčů (test proti seznamu), JSON round-trip beze změny; fuzz/property test 20 000 náhodných vstupů | 0 paniků, 0 porušení validátoru |
| K16-6 | velikost JSON jedné složky | p95 ≤ 8 KiB, max ≤ 16 KiB |
| K16-7 | determinismus | stejný vstup = bajtově stejná složka; dump složek jedné sítě při opakovaném běhu shodný; bez přepínače `networks.jsonl` shodné s binárkou kroku 15 (mimo časy) |
| K16-8 | uzávěry L1: podíl zavřených složek s vlastníkem a expirací | hlásí se (bez prahu; „nelze určit“ je mezera, ne chyba složky) |
| K16-9 | senior review: 30 náhodných případů (různé rodiny, mixy, poruchy, stavy), ruční posouzení podle rubriky (pochopí, co se stalo; ví, co udělat; důvod předání sedí; nic zavádějícího vůči pravdě simulace) | ≥ 80 % „senior ví, co dělat“; 0 zavádějících; každá chyba složky zapsána |

Měření:

- **Simulace bez nového běhu, kde to jde.** Dumpy kroků 14 a 15 (`networks.jsonl`, `diag.jsonl`) nenesou rozhodnutí žebříku s kroky (forenzní stopy kroku 15 nebyly uchovány), takže složku z nich sestavit nejde; z nich se použije jen kontrola K16-7 (shoda `networks.jsonl` bez přepínače). Složky se měří na krátkém soaku s dumpem (`K16_CASE_DUMP=soubor`, jen diagnostika, rozhodnutí neovlivní): nové držené seedy **20269101, 20269102, 20269201, 20269202, 20269301, 20269302, 20269401, 20269402, 20269501, 20269502** (zapsáno dopředu, použít jednou), každý 2 sítě, ramena `off` (20269101, 20269102), `ops` (20269201, 20269202), `elying` (20269301, 20269302), `mixops` (20269401, 20269402), `opsnoise` (20269501, 20269502), vše nad konfigurací `final` kroku 15 s kontrafaktuálem. Idle, maska 0x3FFFFC, nejvýš 8 vláken.
- **Reálná data:** CTU-13 scénář 42 (`tools/k13_replay_zeek.py --v3`), LUFlow 2020-06-19 (`tools/replay_public.py --v3-on`) a EVTX/OTRF replay produkční cestou, vše s `case_files,case_folder`; měří se K16-1 až K16-7 a podíl slepých míst. Pravda tu je jen pro škodlivé hosty (štítky datasetu).
- **K16-9:** výběr 30 případů ze dumpu soaku podle pevného semínka 16 (stratifikace podle stavu a rodiny), posouzení zapsáno do tohoto dokumentu. Hrozba validity: posuzuje autor kódu, ne nezávislý senior; výsledek je horní odhad použitelnosti.

Omezení předem: Council a sol-loop se v tomto kroku podle zadání nespouštějí (odchylka od `CLAUDE.md` daná zadáním). Složka popisuje jen to, co engine viděl; kvalita doporučení je omezená kvalitou detekce, kterou tento krok nemění.

## Implementace

- `src/case_folder.rs` (+ `case_folder/tests.rs`): `build` (čistá funkce), `validate` (K16-1, K16-3, K16-4), `render_text`, `render_html` (escapované, bez stylů). Schéma `salticus.case_folder/1`, 21 klíčů v pevném pořadí.
- `verify_ladder::Decision` nese `notes` (krok, cyklus, značka, LR, text). Rozhodování se nemění (ověřeno K16-7).
- Přepínač `case_folder` (výchozí vypnuto, vyžaduje `case_files`); pipeline v3 staví složku ke každému rozhodnutí žebříku a k zobrazenému nálezu bez rozhodnutí v běhu (stav `open`, apriorní P, výslovně označené); strop 2 000 složek na report s počitadlem `caseFoldersDropped`.
- API: `/runs/{id}/export/cases-txt` a `cases-html` (z `report.json`, UI beze změny).
- Soak: `K16_CASE_DUMP=soubor` (jen měření, rozhodnutí neovlivní). Měřicí skript `tools/k16_case_folders.py`.
- Testy: 12 jednotkových (úplnost, uzávěr s vlastníkem a expirací ze záznamu kontextu i ze seznamu povolených, uzávěr výpadkem s „nelze urcit“, slabý koncový signál není silný důkaz, odmítnutí nadsázky validátorem, pevné klíče a round-trip, escapování HTML, regresní testy z měření níže) a fuzz 20 000 náhodných rozhodnutí (NaN, záporné a > 1 posteriory, prázdné a nečitelné texty, prázdný host): 0 paniků, 0 porušení, determinismus, max ≤ 16 KiB. Integrační test produkční cesty (`tests/engine_v3.rs`): složka ke každému rozhodnutí se shodným P, bez přepínače `caseFolders` chybí. `cargo test --lib`: 641 prošlo, 5 selhalo (jen `broker::*` bez Redis, beze změny); clippy bez varování v nových souborech.

## Výsledky

### K16-7 determinismus (ladicí seed 20261102, 2 sítě, `off`)

Binárka kroku 16 bez dumpu, s dumpem A i s dumpem B: `networks.jsonl` shodný s během kroku 15 (`F:\claude-tmp\k15\det\off-20261102`) ve všech polích kromě časů a pole `wrong_ids`, které přibylo v kroku 15 až po tomto běhu (commit `a381084`). Dump A a dump B: 1 328 složek, bajtově shodné. **Splněno.**

### Držené seedy 20269101 až 20269502 (použity jednou, 10 seedů x 2 sítě, 5 ramen), složky v podobě před opravou

| ramena | složek | potvrzeno / eskalováno / zavřeno | porušení validátoru | p50 / p95 / max B |
|---|---|---|---|---|
| vše | 35 821 | 7 131 / 28 688 / 2 | 2 500 (7,0 %) | 7 113 / 7 827 / 8 538 |
| `off` | 16 045 | 3 408 / 12 635 / 2 | 1 545 | 6 902 / 7 568 / 7 969 |
| `ops` | 3 461 | 241 / 3 220 / 0 | 95 | 7 356 / 7 763 / 8 288 |
| `elying` | 6 754 | 1 564 / 5 190 / 0 | 471 | 7 355 / 8 016 / 8 538 |
| `mixops` | 4 544 | 1 390 / 3 154 / 0 | 307 | 7 244 / 7 827 / 8 284 |
| `opsnoise` | 5 017 | 528 / 4 489 / 0 | 82 | 7 365 / 7 825 / 8 228 |

- K16-1 úplnost: 100 % (povinná pole vyplněna nebo „nelze urcit“; nezávislá kontrola skriptem 0 nálezů). **Splněno.**
- K16-2 pokrytí: každé rozhodnutí žebříku má složku, 0 vynechaných. **Splněno**; v soaku se nestaví složky otevřených nálezů (jen v pipeline).
- K16-3 konzistence: stav, úroveň, P(útok) a uzávěr 100 % shodné s verdiktem. **Splněno.**
- **K16-4 nesplněno: 2 500 složek (7,0 %; 35 % potvrzených) uvádělo „potvrdil žebřík“, ač žádná kontrola nedala podezřelý výsledek.** Žebřík tu potvrdil jen podle apriorní pravděpodobnosti z paměti případů (Case Memory učí P(útok) typu z verdiktů simulovaného analytika; P = 0,90 až 0,96 bez jediného podezřelého kroku). Složka to číselně uváděla („0 nezávislých podezřelých skupin“), ale shrnutí a doporučení („rozhodnout o zásahu“) tvrdily víc, než důkazy dokládají. Je to i nález o enginu (potvrzení bez důkazu), který tento krok podle zadání neladí.
- K16-6 velikost: p95 7 827 B, max 8 538 B. **Splněno** (těsně pod 8 KiB).
- K16-8 uzávěry L1: jen 2 vyvrácení (`connection_timeout_burst`, výpadek služby podle živosti a historie), obě bez vlastníka a expirace („nelze urcit“: provozní příčina nemá schvalovatele). 0 zavřených útoků.
- Důvody předání: slepé místo 99,3 % předaných, chybí pozitivní důkaz neškodnosti 97,6 %, chráněný prostředek 60,9 %, vysoký dopad 56,8 %, konflikt hypotéz 12,8 %. 39,3 % předaných nemá žádný důkaz pro ani proti (jen apriorní P).

### K16-9 senior review na držených seedech (30 případů, semínko 16, složky před opravou)

Výběr stratifikovaný podle stavu, pravdy a rodiny (`tools/k16_case_folders.py sample 30 16`), posouzení autorem (ne nezávislým seniorem). Rubrika: pochopí, co se stalo; ví, co udělat; důvod předání sedí; nic zavádějícího vůči pravdě simulace.

- **Senior ví, co dělat: 17 z 30 (57 %). Zavádějící: 8. K16-9 nesplněno.**
- Chyby složky:
  1. Potvrzení jen podle apriorní P podané jako potvrzený útok (7 případů: `unexpected_traffic` 4x, `packet_rate_spike`, `unmapped_passive_event` na broadcast adrese a další). Zavádějící.
  2. Konvenční podíl 0,8 pro neškodný druh, na který ukazuje provozní diagnóza, vypadal jako změřená pravděpodobnost („chybná konfigurace 0,68“ u `ssh_bruteforce`). Zavádějící (1 případ).
  3. Doporučený krok opakoval kontrolu, která už proběhla bez dat („CaseHistory“ při „historie jen 0 dní“, „ConfigContext“ při „žádný záznam kontextu“ nebo u chráněného nálezu, kde kontext není důkaz). Senior nedostal použitelný další krok (5 případů).
  4. Rovnoměrně rozdělené neškodné druhy se při nízkém P(útok) řadily na první místa („záloha 0,19, aktualizace 0,19, plánovaný skener 0,19“) se stavem „neověřená“, což vypadá jako tři konkrétní vysvětlení.
  5. Kosmetika: tvar „1 nezávislých skupin“.

### Oprava (po měření na držených seedech; držené seedy se znovu nepoužívají)

- Potvrzení bez podezřelého důkazu: shrnutí „označil … za útok jen podle apriorní pravděpodobnosti, bez podezřelého důkazu z kontrol; nutno ověřit“, důvod předání „potvrzeno bez důkazu z kontrol“, doporučení „před zásahem ověřit …, bez podezřelého výsledku nezasahovat“; validátor i skript to vyžadují.
- Neškodné druhy: jen rovnoměrný podíl se zdůvodněním „neškodné celkem X, rozdělení rovnoměrné“, stav „nerozlišená“; druh s neškodným důkazem je jen označen „podporena“ (bez konvenčního čísla).
- Zbývá ověřit: nejdřív kontroly, které v případu neproběhly; provedené bez výsledku až za nimi („znovu má smysl až s novými daty“); u chráněného nálezu bez kontextu a provozní telemetrie. Doporučení vybírá jen z neprovedených.
- Regresní testy `confirmation_without_suspicious_evidence_is_reported_as_prior_only`, `recommendation_skips_checks_that_already_ran_without_data`; fuzz rozšířen o potvrzení bez důkazu.

### Kontrola opravy na ladicích seedech (20261102 `off`, 20261103 `ops`, 20266101 `elying`, 20266105 `mixops`, 20266106 `opsnoise`; po 2 sítích)

- 8 168 složek (758 potvrzeno, 7 410 eskalováno), **0 porušení** validátoru i skriptu, p50 7 276 B, p95 8 159 B, max 8 592 B (p95 těsně pod prahem 8 192 B).
- Potvrzení jen podle apriorní P: 513 z 758 potvrzených (68 %); složka je teď výslovně označuje.
- Doporučený krok eskalovaných: `DnsPivot` 65 %, `CaseHistory` 27 %, `PeerCompare` 7 %.
- Senior review (30 případů, semínko 16; ladicí seedy, tedy jen kontrola opravy, ne nezávislé měření): **ví, co dělat 24 z 30 (80 %), zavádějící 0.** Zbylých 6 jsou eskalované případy bez důkazu pro i proti (`packet_rate_spike` 3x, `connection_timeout_burst`, `service_unreachable`, `unexpected_traffic` s P = 0,78), kde složka doporučí `DnsPivot`, kontrolu, která u dostupnostního nálezu nic nerozliší a kterou program sám neumí (ruční dotaz do dns.log). Složka tu poctivě ukazuje, že engine nemá co předat.

### Reálná data produkční cestou (`final` + `case_files,case_folder`)

| dataset | složek (otevřené / eskalované) | bez složky | neshoda s verdiktem | porušení | p95 / max B | bez jakéhokoli důkazu |
|---|---|---|---|---|---|---|
| CTU-13 scénář 42 (10 oken) | 22 (11 / 11) | 0 | 0 | 0 | 7 708 / 7 735 | 90,9 % |
| CTU-13 scénář 54 (33 oken) | 34 (17 / 17) | 0 | 0 | 0 | 7 798 / 7 956 | 82,4 % |
| LUFlow 2020-06-19 (28 oken) | 1 025 (522 / 503) | 0 | 0 | 0 | 6 532 / 8 029 | 97,8 % |

Detekce beze změny proti kroku 15 (CTU-42: 11 zobrazených nálezů o infikovaném hostu, 0 o jiných). Žebřík na reálných datech nic nepotvrdí ani nevyvrátí (bez kontextu, sondy a koncové telemetrie), takže složky jsou úplné, ale skoro bez důkazů; hlavním obsahem je seznam slepých míst a co chybí.

## Shrnutí prahů

| práh | výsledek |
|---|---|
| K16-1 úplnost | splněno (100 %, soak i reálná data) |
| K16-2 pokrytí | splněno (0 rozhodnutí ani zobrazených nálezů bez složky, 0 zahozených) |
| K16-3 konzistence | splněno (100 %) |
| K16-4 netvrdí víc | **nesplněno na držených seedech (7,0 %)**; po opravě 0 na ladicích seedech a reálných datech |
| K16-5 schéma | splněno (pevné klíče, round-trip, fuzz 20 000 bez paniky a porušení) |
| K16-6 velikost | splněno (držené p95 7 827 B; ladicí po opravě p95 8 159 B, těsně) |
| K16-7 determinismus | splněno |
| K16-8 uzávěry L1 | 2 uzávěry, 0 % s vlastníkem a expirací (výpadek nemá schvalovatele) |
| K16-9 senior review | **nesplněno na držených seedech (57 %, 8 zavádějících)**; po opravě 80 %, 0 zavádějících na ladicích seedech (autor = posuzovatel) |

## Co se nepodařilo

- K16-4 a K16-9 na držených seedech neprošly; oprava je ověřena jen na ladicích seedech a reálných datech. Nezávislé ověření potřebuje nové držené seedy a posouzení jiným člověkem než autorem.
- EVTX/OTRF: `endpoint ingest` odmítne všechny události OTRF (cmd_psexec_lsa_secrets_dump) jako staré (`rejected_time` 57 z 57) a `endpoint replay-evtx` nevolá žebřík; bez posunu časů (zásah do reálných dat) a bez síťového inventáře hostů z datasetu z nich složka nevznikne. Nepřehráno.
- Doporučený krok je „nejlevnější dosud neprovedená kontrola“, ne kontrola s nejvyšší rozlišovací schopností pro typ nálezu; u dostupnostních nálezů doporučí DNS pivot, který nic nerozliší a program ho sám neumí (složka neříká výslovně, že jde o ruční kontrolu).
- Uživatel jako aktér není v datech žebříku nikdy; složka vždy hlásí „nelze urcit“. Proces jen z textu koncového kroku.
- „Slepé místo“ je důvodem předání u 99 % případů (skoro každý případ má kontrolu bez dat), takže jako důvod málo rozlišuje.
- V soaku složky nemají pokrytí senzory ani incidenty (hlášeno „nelze urcit“); v pipeline ano.
- Uzávěry L1 v tomto světě skoro nejsou (2 z 35 821), vlastník a expirace uzávěru jsou ověřeny jen jednotkovými testy.
- Nález o enginu mimo rozsah kroku: 35 % (držené) až 68 % (ladicí) potvrzení žebříku nemá žádný podezřelý výsledek kontroly; rozhoduje apriorní P z paměti případů. Patří do další práce na politice potvrzování, ne do ladění zde.
- Council a sol-loop se podle zadání nespouštěly; review je jen autorské.
