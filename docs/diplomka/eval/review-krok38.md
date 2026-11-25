# Review kroků 33 až 39 (stav, souběh, zásahy do seskupení)

Provedeno čtením kódu autorem (jiného posuzovatele nebylo k dispozici, protože souběžně smí běžet jen jeden pomocný proces); není to nezávislé review a nesmí se tak citovat. Rozsah: `src/retro.rs` (perzistence po událostech, `incidents_v3`, `assemble`), `src/correlation_layer.rs` (`run`, klíče, `attach_related`, souhrn), `src/incident_overrides.rs`, endpointy v `src/server.rs`, napojení v `src/pipeline/v3.rs`.

## Nálezy a rozhodnutí

| # | nález | závažnost | rozhodnutí |
|---|---|---|---|
| 1 | `flush` mazal seznam změněných událostí ještě před potvrzením transakce; při chybě zápisu by se změny ztratily | střední (ztráta historie korelace) | opraveno: seznam se maže až po `commit` |
| 2 | `load_db` při poškozeném řádku nebo mezeře v číslech zahodil **celou zbývající historii** | střední | opraveno: zahodí se jen starší část a poškozený řádek, novější události zůstanou; test s poškozeným řádkem |
| 3 | serializace události v `flush` při chybě tiše zapsala prázdný řetězec | nízká | opraveno: chyba se vrací |
| 4 | ruční sloučení incidentů nezachovalo hrany (`links`) a odpojení nechalo hrany odpojeného nálezu | nízká (jen vysvětlitelnost) | opraveno: hrany se slučují, přidá se hrana `manual`, hrany odpojeného nálezu zanikají; kostra po odpojení může být nesouvislá (zdokumentováno) |
| 5 | identifikátory nálezů v ručních zásazích se nevalidovaly (délka, řídicí znaky, `a = b`) | nízká (kapacita databáze) | opraveno: validace v `submit`, test |
| 6 | endpointy `POST /incidents/override` a revoke vyžadují `findings.write` a CSRF hlavičku (stejný vzor jako zpětná vazba); `GET` jen `runs.read` | – | bez nálezu, ověřeno čtením |
| 7 | korelace nemění `Finding`, stav paměti nálezů ani zavření; `run` dál zapisuje účetní knihu rozhodnutí jako dřív | – | bez nálezu; test H1 (zobrazené nálezy beze změny) ve všech měřeních |

## Neopraveno nebo nezměřeno (přiznáno)

- Ruční zásah `detach` se neprojeví v `related`: související incidenty se počítají z historie, ne z upravených incidentů; odpojený nález tak může být nadále spojen přes `related`.
- Souběžné běhy téhož pracovního prostoru: ochrana je jen `busy_timeout` SQLite (5 s) a transakce; samostatný zámek běhu jsem neprověřoval.
- Přežití restartu celého procesu pro ruční zásahy a dvacet reálných přerušení uprostřed běhu nebyly provedeny; ověřen je jen jednotkový test a opakování okna po simulovaném pádu před zápisem.
- Prahy hubů (25 a 100) a okno 6 h jsou zvolené předem, na datech neladěné, a nejsou ověřené mimo měření v krocích 35 až 39.

## Co z toho plyne

Nálezy 1 a 2 byly skutečné chyby ve stavu, které jednotkové testy původně nezachytily; po opravě jsou pokryty testem. Tento dokument nenahrazuje nezávislé review a dokud se neudělá, kroky 38 (perzistence), ruční zásahy a stabilní klíč se nesmějí označit za hotové ve smyslu CLAUDE.md.

## Celé `cargo test --lib` po opravách

Selhání: pět testů `broker` (vyžadují Redis, který tu neběží), `identity_lab::identity_resolver_correctly_classifies_real_dhcp_renewal_and_nat_swap` (už dříve známé) a `platform::worker_cycle_renews_lease_during_long_executor_preventing_concurrent_double_claim`, který při samostatném spuštění prochází (9 s) a při plném běhu spolu s jinou zátěží selhal; považuji ho za citlivý na čas, příčinu jsem nezkoumal. Pro dotčené moduly (`correlation_layer`, `retro`, `incident_overrides`, `case_folder`, `engine`, `pipeline`, `server`) testy procházejí. Součty celého běhu jsem neuložil (výpis byl zkrácen), proto uvádím jen seznam selhání.

## Úplný běh `cargo test --lib` (26. 11. 2026, po krocích 38 až 43)

799 prošlo, 7 selhalo, 32 ignorováno (658 s; celý výpis uložen mimo repozitář). Selhání: pět testů `broker` (vyžadují Redis), `identity_lab::identity_resolver_correctly_classifies_real_dhcp_renewal_and_nat_swap` (dříve známé) a `platform::worker_cycle_does_not_block_on_lease_renewal_when_executor_finishes_quickly`; ten i `worker_cycle_renews_lease_…` (selhal v dřívějším běhu) při samostatném spuštění procházejí. Jde o testy citlivé na čas při zátěži (běh souběžně s dlouhými měřeními); příčinu jsem nezkoumal. Žádné selhání v modulech korelace.
