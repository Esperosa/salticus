# Předregistrace kroku 34: kauzální seskupení incidentů (`corr_v3`)

Zapsáno a commitnuto před měřením. Navazuje na `predreg-krok33.md` a `plan-korelace.md`.

## Proč

Vývojový běh kroku 33 (seed 33, použitý jen k odladění skriptů) ukázal:

- seskupení podle sdílené IP (B1) má párové F1 0,73 (úplnost 1,0, přesnost 0,58, 11 z 28 skupin slévá souběžné řetězce přes sdílený vnější cíl nebo server);
- produkční v1 má F1 0,26 (úplnost 0,16), v2 nespojila žádný řetěz;
- příčiny, ověřené v datech: (1) fáze skenu vzniká jako nález bez `host_key` a korelace ho zahodí; (2) v2 spojuje jen stejného aktéra a stejný protějšek, takže řetěz A→V, pak V→X nikdy nespojí; (3) v1 spojuje přes každý sdílený host a slévá.

Z toho vznikl `corr_v3` (commit `6009d5a`, vypnuto ve výchozím stavu): spojuje (a) stejného aktéra a stejný protějšek, (b) protějšek dřívějšího nálezu, který se pak sám stane aktérem, (c) oběť z nálezu bez hosta s nálezy, kde je ta adresa aktérem nebo protějškem, (d) téhož aktéra u dvou útočných nálezů; dva nálezy se nespojují jen kvůli stejnému protějšku; klíč, který by spojil víc než 25 nálezů, je hub a dál nespojuje. Pravidla jsem navrhl podle vývojových dat (seed 33) a podle struktury řetězců, výsledky testu kroku 33 (seed 133) jsem při návrhu neměl.

## Data a zmrazení

- Generátor a vyhodnocení beze změny (`tools/k33_chain.py`, `tools/k33_corr.py`, commit `44e2ef2`). Test: nový seed 233 (nepoužitý v žádném dřívějším kroku), 40 řetězců, vygeneruje se až po tomto commitu a spustí jednou.
- Běhy: A (`corr_v2` vypnuto, v1) a C (`corr_v2` a `corr_v3` zapnuto), jinak stejná konfigurace jako v kroku 33 (v3, `attempts`, `attr_calib`, `upload_horizon`, `case_files`). Ramena B0, B1, B2 se počítají ze zobrazených nálezů běhu C.
- Prahy (`INCIDENT_GAP_S` 6 h, `MAX_KEY_DEGREE` 25) jsou zmrazeny; změna po měření by byl nový krok s novým seedem.

## Hypotézy a rozhodovací pravidla

- **H1 (bez ztráty):** množina zobrazených `finding_id` v běhu A a C je totožná.
- **H2 (šum a hub):** C má ≤ 45 incidentů za 3 dny; největší incident obsahuje ≤ 20 % zobrazených nálezů; žádný incident mimo kolizní dvojice nesloučí nálezy dvou řetězců.
- **H3 (zisk):** párové F1 ramena C překoná B1 o ≥ 0,10, dolní mez 95 % párového bootstrapu rozdílu C − B1 je > 0 a C překoná B2.
- **H4 (čistota, dodatek):** počet slitých skupin (nálezy ≥ 2 řetězců) ramena C je nižší než u B1.
- Popisně: B3 (v1) proti C, fragmentace, úplnost.

## Co z výsledku plyne

- H1 až H3 platí: `corr_v3` jde do dalšího kroku (důvod spojení u každé hrany, soak na domácí síti), výchozí profil až po soaku.
- H3 neplatí, ale H4 platí: zlepšení čistoty bez zisku F1 se napíše jako částečné; rozhoduje se podle ceny úplnosti.
- H2 nebo H1 neplatí: oprava chyby před čímkoli dalším.

## Omezení

Syntetické řetězce s unikátními IP účastníků; třetina řetězců je ve dvojicích se sdíleným cílem. Fáze skenu nese jen adresu oběti (zdroj skenu se v nálezu bez hosta neztrácí jen u spárovaných událostí), takže kauzální vazba skenu na další fáze jde přes oběť, ne přes útočníka. Platí pro tento typ řetězců, nezobecňuje se.
