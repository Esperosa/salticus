# Datasety kroku 9: stav, adaptéry a přehrání

Stav k 2026-11-14. Pravidla: labely datasetů se nemíchají do jednoho plochého schématu (každý dataset má vlastní adaptér, vlastní schéma a vlastní vyhodnocení); do `dataset-registry.md` jde licence z oficiální stránky, SHA-256, URL a datum stažení; zdroje, které vyžadují žádost nebo registraci, jsou zapsané jako „vyžaduje žádost, neodesláno“ a nic se neodeslalo. Zamčená testovací část se pouští jednou.

## Stav po datasetech

| dataset | stav | adaptér / přehrání | poznámka |
|---|---|---|---|
| IoT-23, CTU-13 | dříve staženo | adaptéry `eval::sources::{iot23,ctu13}`, přehrání `tools/replay_public.py` | licence CC BY-NC-SA 4.0, výzkum |
| CIC-IDS2017, UNSW-NB15 | dříve staženo (výřezy) | adaptéry `eval::sources::{cicids2017,unsw_nb15}` | viz registr |
| CSE-CIC-IDS2018 | staženo 4 prefixy (240 MB) | bez adaptéru; CSV z CICFlowMeteru nemá sloupce IP adres | nelze přehrát produkční cestou (potřebuje zdroj a cíl); lze jen vyhodnotit rysy toků; řádky nejsou seřazeny podle času, 12 vložených hlaviček v `thu-01-03` |
| LUFlow | staženo 4 denní soubory (76,6 MB) | `tools/datasets/luflow_to_zeek.py` + `tools/replay_public.py` | štítky `benign` / `malicious` / `outlier`; `outlier` = neoznačeno zdrojem, mapuje se na Unknown, nikdy na Benign; adresy jsou anonymizovaná čísla, mapují se na 10.x.y.1 |
| HAI | staženo (3 soubory) | bez adaptéru | časové řady procesu ICS, ne toky; zapsáno pro budoucí použití |
| OTRF Security-Datasets, EVTX-ATTACK-SAMPLES | staženo (výřezy) | parsery koncové telemetrie kroku 8 (jen testy parserů) | štítek na úrovni události není, pravda je v metadatech |
| MAWI | staženo prvních 60 MB (hlavičky) | bez adaptéru | neškodný provoz bez štítků |
| CICIoT2023, LANL, TON_IoT, Bot-IoT, ICS-Flow, DARPA OpTC, Kitsune | nestaženo | - | vyžaduje žádost, formulář, přihlášení nebo je mimo limit velikosti; důvod u každého v registru |

## Přehrání LUFlow celou produkční cestou

Vstup: první 200 000 toků souboru 2020.06.19, 30minutová okna, `salticus-program beh spust` v režimu v3 s `protect`, rozsah 10.0.0.0/8. Soubor pokrývá jediný den, takže „zralé období“ v tabulce znamená okna po prvních 48 h podle času nástroje, ne skutečně dlouho učený profil; spolehlivé měření zralého období na LUFlow není možné (soubory jsou z různých dnů). Zamčená testovací část se nepoužila.

Toků 200000, oken 28 po 1800 s, rozsah 10.0.0.0/8, škodlivých hostů podle štítků 259, selhaných běhů 0, protect=True.

| období | oken | toků | zobrazeno | na škodlivém hostu | jinde | chráněných | auto zavřeno | žebřík (potvrzeno/vyvráceno/eskalováno) | škodliví hosté zobrazeni | ostatní hosté zobrazeni |
|---|---:|---:|---:|---:|---:|---:|---:|---|---:|---:|
| cold | 2 | 19 | 1 | 0 | 1 | 0 | 0 | 0/0/0 | 0 z 259 | 1 |
| mature | 26 | 199981 | 1076 | 15 | 1061 | 15 | 0 | 0/0/1057 | 1 z 259 | 1 |

Degradace pokrytí (oken s důvodem): immature_profiles 28, no_ids 28




Výklad: výsledek je slabý a je třeba ho číst opatrně. Adresy LUFlow jsou anonymizované, takže hranice „uvnitř“ a „venku“ je v přehrání umělá (celý blok 10/8 je uvnitř) a odpovídá spíš vnitřnímu provozu než hraničnímu. Příčina nízkého podílu nebyla rozebrána (hypotéza: škodlivé zdroje jsou převážně skenery, které produkční cesta bez hraniční perspektivy nevidí; neověřeno). Přehrání proto neslouží jako důkaz detekce ani jako ladicí vstup, jen jako kontrola, že produkční cesta data zpracuje bez selhání (0 selhaných běhů).
