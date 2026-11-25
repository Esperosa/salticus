# Předregistrace kroku 33: kvalita korelace na vícefázových řetězcích

Zapsáno a commitnuto před měřením. Navazuje na `plan-korelace.md`.

## Otázka

Seskupuje korelace (incidenty) nálezy jednoho útoku do jednoho incidentu lépe než triviální seskupení podle sdílené IP, a to bez ztráty zachycení a bez nárůstu šumu?

## Data a zmrazení

- Pozadí: skutečný `conn.log` z domácí sítě (3 dny, 283 tisíc toků). Řetězce vkládá `tools/k33_chain.py` (zmrazený commit `44e2ef2`), 40 řetězců: 10 simple, 10 pivot, 20 v kolizních dvojicích (sdílený vnější cíl a obětní server).
- Vyhodnocení: `tools/k33_corr.py eval` (zmrazeno stejným commitem). Nález se přiřadí řetězci jen tehdy, když zmiňuje IP aktéra právě jednoho řetězce (útočník, oběť, pivot); sdílené adresy řetězec neurčují.
- Dev: seed 33 (už vygenerovaný), použit jen k odladění skriptů; kód produkce se podle něj neladí. Test: seed 133, vygeneruje se až po tomto commitu a spustí se jednou.
- Konfigurace obou běhů: v3 + `attempts`, `attr_calib`, `upload_horizon`, `case_files`. Běh A: `corr_v2` vypnuto (seskupení v1, čas běhu). Běh B: `corr_v2` zapnuto (v2, čas nálezu). Okna 30 min, trvalý workspace.

## Ramena (stejné zobrazené nálezy, jiné seskupení)

B0 každý nález zvlášť. B1 spojení podle sdílené IP. B2 náhodné seskupení se stejnými velikostmi jako B1. B3 incidenty produkce v1 (běh A). B4 incidenty produkce v2 (běh B).

## Hypotézy a rozhodovací pravidla

- **H1 (bez ztráty):** množina zobrazených `finding_id` je v běhu A a B totožná (rozdíl 0), a pokrytí řetězců nálezy je stejné. Korelace jen anotuje; jakýkoli rozdíl je chyba a krok se zastaví.
- **H2 (šum):** B4 má ≤ 15 incidentů za den (3 dny, tedy ≤ 45) a žádný incident neobsahuje nálezy z více než jednoho řetězce mimo kolizní dvojice.
- **H3 (zisk):** párové F1 (dvojice nálezů ze stejného řetězce ve stejné skupině) B4 překoná B1 o ≥ 0,10 a dolní mez 95 % párového bootstrapu (2000 vzorků řetězců) rozdílu B4 − B1 je > 0; B4 zároveň překoná B2.
- Popisně, bez rozhodnutí: čistota, počet slitých skupin, fragmentace, úplnost, B3 proti B1.

## Co z výsledku plyne

- H3 platí: pokračuje se krokem K6 (důvod spojení, strukturované indikátory) a K7.
- H3 neplatí: v2 nestačí a opodstatňuje entitní graf s kauzálním řetězením fází (L1 až L4 z `plan-korelace.md`); závěr se napíše jako negativní a nic se nezapíná.
- H1 neplatí: oprava chyby před čímkoli dalším.

## Omezení, která se přiznají předem

Útoky jsou syntetické řádky `conn.log` bez obsahu, intenzity volil autor; řetězce mají unikátní IP účastníků, takže přiřazení podle IP je jednoznačné. Výsledek platí pro tento typ řetězců a toto pozadí, ne pro útočníky obecně. 40 řetězců dává široké intervaly.
