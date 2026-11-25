# Předregistrace kroku 35: `corr_v3` po opravách, silnější baseline, dva nové tvary řetězců

Zapsáno a commitnuto před měřením. Navazuje na `plan-korelace-final.md` (fáze F0 a M1 až M5). Kód `corr_v3` po opravách F0 je commit se zprávou „fix: korelace corr_v3 (orez ponecha nejnovejsi …“; generátor `tools/k35_chain.py` a vyhodnocení `tools/k35_corr.py` jsou zmrazené tímto commitem.

## Změny proti kroku 34

- Opravy: ořez ponechá nejnovější incidenty; hub se počítá v časovém okně (25 pro protějšek a oběť, 100 pro aktéra); index událostí a doplnění důkazů; pořadí v jednom okně podle fáze; nálezy bez hosta na téže oběti se nespojují.
- Baseline B1b: sdílená IP s oknem 6 h a mezí hubu 25 (silnější než B1 z kroku 34).
- Data: 60 řetězců, 5 tvarů po 12 (simple, pivot, fanout, samewin, collision jako 6 dvojic). Pravda obsahuje `all_ips` (i sdílené adresy), takže se odděluje čisté pozadí.
- Metriky navíc: kontaminace (podíl nálezů pozadí v incidentech s řetězcem), počet čistě pozaďových incidentů, churn (podíl nálezů přesunutých mezi sousedními okny do incidentu, který neobsahuje celý původní).

## Data a běhy

Dev: seed 35 (jen kontrola skriptů a funkčnosti, nic se podle něj neladí). Test: seed 335, vygeneruje se po tomto commitu a spustí jednou. Konfigurace jako dřív (v3, `attempts`, `attr_calib`, `upload_horizon`, `case_files`); běh A bez `corr_v2` (v1), běh C s `corr_v2` a `corr_v3`. Okna 30 min, 125 oken.

## Hypotézy a pravidla

- **H1 (bez ztráty):** množina zobrazených `finding_id` v A a C je totožná.
- **H2a (pozadí):** C má ≤ 30 čistě pozaďových incidentů za 3 dny (10 denně).
- **H2b (řetězce):** incidenty obsahující nález řetězce ≤ 66 (60 řetězců, kolizní dvojice se smí sloučit).
- **H2c (kontaminace):** podíl nálezů pozadí v incidentech s řetězcem ≤ 0,05.
- **H3 (zisk):** párové F1 C − B1b ≥ 0,10, dolní mez 95 % bootstrapu (přes jednotky pravdy) > 0; navíc C není horší než B1b o víc než 0,05 v žádném ze 5 tvarů.
- **H4 (churn):** podíl přesunutých nálezů ≤ 0,10.
- Popisně: slité kolizní dvojice (z 6), úplnost, fragmentace, B1 a v1.

## Rozhodnutí z výsledku

- Vše platí: pokračuje se na skutečná data (K9).
- H3 neplatí v některém tvaru: úprava pravidel až v novém kroku s novým seedem a negativní výsledek se zapíše.
- H2a nebo H2c neplatí: korelace není pro provoz použitelná, řeší se příčina před K9.
- H1 nebo H4 neplatí: oprava chyby před čímkoli dalším (tentokrát se předregistrace dodrží).
- Slité kolizní dvojice > 0 z 6: K12 (zdroj skenu) se spouští; jinak se škrtá.

## Omezení

Syntetické řetězce stále od stejného autora jako pravidla; nové tvary (fanout, samewin) pravidla neviděla a jsou kontrolou, ne důkazem nezávislosti. Platnost pro skutečné útočníky ověří až K9.
