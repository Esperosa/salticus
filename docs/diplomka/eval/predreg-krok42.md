# Předregistrace kroku 42: řetězení jen mezi nálezy s mapovanou taktikou (`corr_tactic`)

Zapsáno před měřením. Navazuje na `impl-krok41.md` (perkolace: největší incident 264 z 347 nálezů, kontaminace 0,91).

## Změna

`corr_tactic` (vyžaduje `corr_v3`): pravidla `peer_actor`, `victim_actor`, `actor_victim`, `actor_attack` spojují jen nálezy, které mají mapovanou taktiku ATT&CK (`tactic_of`); běžné relace (`interactive_session`, `long_lived_tunnel`, nálezy bez hosta) přes ně už mosty nevytvářejí. Ostatní pravidla (stejný aktér a protějšek, sdílená oběť, sdílený vnější protějšek) beze změny. Mapování rozšířeno o `bruteforce_attempts` (credential-access) a `outbound_scan` (discovery), aby syntetické i skutečné řetězce nepřišly o taktiku. Změna je navržena podle dne Week6_Day3 (dev, použit v kroku 41), proto je tento den popisný.

## Data

- **Dev (popisně):** Week6_Day3_06302021 (krok 41).
- **Test (jednou):** Week6_Day4_07012021 (156 259 toků po odstranění duplicit; kampaň APT, hostitelé 10.1.3.17, 10.1.3.8, 10.1.5.21, 10.8.10.84, 192.168.0.11). Před předregistrací jsem z něj četl jen souhrn labelů pro pravdu.
- **Regrese na syntetice:** řetězce seed 335 (použity v kroku 35), jen kontrola, že řetězení nic neztratilo.
- Kód zmrazen na commitu **262474a**; prahy a mapování beze změny.

## Ramena

A (v1), C (`corr_v2`+`corr_v3`+`corr_ext`+`corr_related`), Ct (C + `corr_tactic`), U (`corr_union`), offline B1 a B1b. Úroveň normal; metriky jako v kroku 40.

## Hypotézy a pravidla (rameno Ct, test Week6_Day4)

- **H1:** zobrazené nálezy v A a Ct totožné.
- **H2:** 0 duplicitních položek v incidentech Ct.
- **H3 (perkolace):** největší incident Ct ≤ 20 % zobrazených nálezů.
- **H4 (čistota):** kontaminace Ct nižší než kontaminace C a než B1b o ≥ 0,20.
- **H5 (bez ztráty):** počet adres kampaně v nejlepším incidentu Ct ≥ počet u C a úplnost nejlepšího incidentu Ct ≥ 0,5 × úplnost u C.
- **H6 (syntetika bez ztráty):** párové F1 Ct na seed 335 ≥ 0,95 (krok 35: C 0,988).
- Pokud test nebude informativní (zobrazených nálezů kampaně < 10), H3 až H5 se nehodnotí.

## Rozhodnutí z výsledku

- H1 až H6 platí: `corr_tactic` se doporučí do shadow konfigurace pro větší sítě.
- H3 nebo H4 neplatí: perkolace se tímto pravidlem nevyřeší; zapsat negativně a hledat jiný mechanismus (omezení velikosti komponenty, role server a klient).
- H5 nebo H6 neplatí: pravidlo škodí zachycení řetězců, zamítnout.

## Omezení

Jedna kampaň na test; privátní adresy; test je ze stejné sady a stejné infrastruktury jako dev den, takže nejde o jinou síť.
