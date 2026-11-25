# Předregistrace kroku 43: jádro incidentu z nejsilnějších vazeb + `related` (`corr_core`)

Zapsáno před měřením. Navazuje na `impl-krok42.md` (žádné jednoduché omezení nedosáhlo vysoké úplnosti i nízké kontaminace).

## Změna

`corr_core` (vyžaduje `corr_v3`): do **jádra incidentu** vstupují jen nejsilnější vazby (stejný aktér a protějšek, sdílená oběť nálezu bez hosta, sdílený vnější protějšek, oběť s nálezem, který na ni míří). Vazby přes role aktér a protějšek (`peer_actor`, `victim_actor`, `actor_victim`, `actor_attack`), které v podnikové síti perkolují, se do jádra nepočítají a zůstávají jen jako odkazy `related` (komponenta `incidents_union` s důvodem). Úplnost se měří uzávěrem přes `related`, čistota jádrem.

## Data

- **Test (jednou):** DAPT2021 Week5_Day3_06232021 (158 797 toků po odstranění duplicit; kampaň APT, hostitelé 10.1.3.8, 10.1.5.21, 10.8.10.84, 192.168.0.11; fáze Establish Foothold a Lateral Movement). Před předregistrací jsem z něj četl jen souhrn labelů pro pravdu.
- **Popisně (data už použitá):** Week6_Day3, Week6_Day4, LLDOS ×2, PicoDomain; **regrese na syntetice** seed 335.
- Kód zmrazen na commitu **36812a3**.

## Ramena a metriky

A (v1), C (`corr_v2`+`corr_v3`+`corr_ext`+`corr_related`), Kc (C + `corr_core`), U (`corr_union`); offline B1b. Úroveň normal; jádro (INC) a uzávěr (INC_closure).

## Hypotézy a pravidla (rameno Kc, test Week5_Day3)

- **H1:** zobrazené nálezy v A a Kc totožné. **H2:** 0 duplicitních položek v jádrech Kc.
- **H3 (perkolace):** největší jádro Kc ≤ 20 % zobrazených nálezů.
- **H4 (čistota jádra):** kontaminace jádra Kc ≤ 0,60.
- **H5 (úplnost uzávěru):** uzávěr Kc má úplnost ≥ 0,60 a obsahuje ≥ 2 adresy kampaně v nejlepší skupině.
- **H6 (syntetika):** uzávěr Kc na řetězcích seed 335 má párové F1 ≥ 0,95.
- Pokud zobrazených nálezů kampaně < 10, test je neinformativní a H3 až H5 se nehodnotí.

## Rozhodnutí z výsledku

- H1 až H6 platí: `corr_core` + `related` se doporučí jako varianta pro shadow konfiguraci větších sítí a otevírá se K16 s ní.
- H3 nebo H4 neplatí: jádro stále perkoluje nebo je kontaminované; zapsat negativně.
- H5 nebo H6 neplatí: uzávěr nenahradí úplnost; zamítnout.

## Omezení

Jedna kampaň na test; privátní adresy; stejná infrastruktura jako předchozí dny; uzávěr je tranzitivní a jediný falešný odkaz ho může rozšířit.
