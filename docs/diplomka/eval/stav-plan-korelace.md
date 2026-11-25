# Stav plánu korelace (k 25. 11. 2026)

Podle `plan-korelace-final.md`. „Hotovo“ znamená splněné kritérium kroku s dokumentem; uvedeno, co ne.

| krok | stav | důkaz nebo důvod |
|---|---|---|
| F0-1 až F0-6 (opravy: ořez nejnovějších, hub v okně, index, doplnění důkazů, pořadí v okně, sdílená oběť) | hotovo | testy v `correlation_layer`, `retro`; commit `fix: korelace corr_v3 …` |
| M1 silnější baseline B1b | hotovo | `k35_corr.py` |
| M2 kontaminace | hotovo | `k35_corr.py`, `k36_lldos.py` |
| M3 druhý tvar řetězců | hotovo | `k35_chain.py` (fanout, samewin) |
| M4 předregistrace | hotovo | `predreg-krok35.md`, `predreg-krok36.md` |
| M5 churn po oknech | hotovo | 0 přesunutých nálezů z 88 810 (syntetika) a 70 326 (domácí síť) |
| K9 skutečná data | částečně | DARPA 2000 LLDOS 1.0 a 2.0.2, PicoDomain a DAPT2021 (4 skutečné kampaně, N = 1 každá; DAPT2021 neinformativní, 1 nález kampaně za den); CTU-13 a IoT-23 neprovedeno (jednohostové botnety); výsledek: finální konfigurace nad jednoduchým seskupením nic zřetelně nepřidává (`impl-krok36.md`, `impl-krok39.md`, `impl-krok40.md`); jediný přínos prokázaný na všech datech je odstranění duplicit nálezů ve v1 |
| K10 šum pozadí | hotovo | 7,7 incidentů/den na 2,6 dne domácí sítě (cíl ≤ 15), největší incident 5,7 % zobrazených (jeden hub-host, 466 nálezů) |
| K11 důvod spojení | hotovo | `Incident.links[]` (pravidlo, adresa, odstup; kostra incidentu) a `related[].via`; test: počet hran = nálezy − 1 |
| K12 zdroj skenu | odloženo | po F0-4 kolizní dvojice už nesplývají; nález skenu bez zdroje zůstává limitem |
| K13 perzistence a idempotence | hotovo | tabulky `retro_events`, opakování okna po pádu dává shodný výstup (test); 20 reálných přerušení procesu neprovedeno |
| K14 ruční zásahy | hotovo | `incident_overrides`, endpointy, append-only audit; test jednotek a revokace; test přežití restartu procesu neprovedeno |
| K15 výkon a degradace | částečně | 0,2 s CPU na 50 000 událostí; mezery pokrytí v souhrnu; paměť a referenční hardware (Pi 4, N100) neměřeno |
| S1 souhrn dne | hotovo | `daySummary` v reportu (klíč, hosté, fáze, typy nálezů, časy, nový, mezery pokrytí) |
| K16 shadow soak 14 dní | nelze zkrátit | konfigurace `labs/shadow/salticus.shadow.toml` zapíná korelaci; trvá 14 dní reálného času |
| K17 rozhodnutí o výchozím profilu | čeká na K16 | tabulka níže |

## Hlavní výsledky

- Produkční v1 byla na vícefázových syntetických řetězcích horší než triviální seskupení podle IP (F1 0,26 proti 0,78); opravy a `corr_v3` (+ `corr_ext`, `corr_related`) to na syntetice zvyšují na 0,99, ale **na skutečných kampaních LLDOS kauzální pravidla bez dalších úprav nic nespojí a triviální seskupení je stejně dobré nebo lepší** (`impl-krok36.md`). Přínos kauzálního seskupení nad jednoduchým není prokázán.
- Skutečný kompromis je úplnost proti čistotě; řeší ho `related` (silné vazby tvoří incident, slabé se odkážou s důvodem), ne tvrdé slučování. Prokázáno popisně na LLDOS, ne nezávisle.

## Tabulka pro rozhodnutí o výchozím profilu (K17)

| kritérium | cíl | změřeno |
|---|---|---|
| zobrazené nálezy beze změny | 0 rozdílů | 0 (všechna měření) |
| pozaďové incidenty | ≤ 15/den | 7,7/den |
| největší incident | ≤ 20 % | 5,7 % (jeden hub-host) |
| klíč incidentu stabilní | ≥ 99 % | 99,95 % (1 ze 1 896) |
| churn nálezů | ≤ 10 % | 0 % |
| výkon 50 000 událostí | ≤ 2 s CPU | 0,2 s |
| úplnost na skutečné kampani (samotný incident) | předem daný práh | 0,39, 0,40 a 0,38 (nízká); uzávěr přes `related` 0,71, 0,80, 0,46 |
| nezávislý přínos nad silnou baseline | dolní mez > 0 | **neprokázáno** (LLDOS ×2 a PicoDomain: srovnatelné s B1b; H3 a H4 kroku 39 neplatí) |
| 14denní soak | bez porušení | neproběhl |

Doporučení: výchozí profil nezapínat. Kauzální pravidla (`corr_v3`, `corr_ext`) se na třech skutečných kampaních neprokázala jako lepší než jednoduché seskupení s oknem a mezí hubu; hodnota opravené korelace je v opravách (čas nálezu, nálezy bez hosta, hub, perzistence, stabilní klíč, souhrn dne, důvody hran). Korelaci (`corr_v2` + `corr_v3` + `corr_ext` + `corr_related`) nechat zapnout v shadow konfiguraci pro soak.

## Co zbývá a proč to nejde autonomně hned

K16 (14 dní provozu), nezávislé označení užitečnosti analytikem, měření na referenčním hardwaru, další skutečné vícefázové kampaně (v seznamu rešerše: Unraveled, AIT Alert Dataset, LMDG; u AIT jen alerty, tedy nelze měřit vstup z toků).
