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
