# Krok 43: jádro incidentu z nejsilnějších vazeb + `related` (`corr_core`)

Podklad: `predreg-krok43.md`, kód zmrazen commitem `36812a3`. Test: DAPT2021 Week5_Day3_06232021 (158 797 toků, 130 zobrazených nálezů, z toho **8** kampaně). Popisně: Week6_Day3 a Week6_Day4 (data už použitá), syntetické řetězce seed 335 (regrese).

## Výsledek

| data | rameno | incidenty | úplnost | kontaminace | největší | poznámka |
|---|---|---|---|---|---|---|
| w5d3 (test) | v1 | 4 | 0,50 | 0,95 | 80 | 48 duplicit |
| w5d3 | C | 10 | 0,75 | 0,92 | 75 | |
| w5d3 | **Kc jádro** | 18 | 0,50 | **0,40** | **5** | |
| w5d3 | Kc uzávěr | 6 | 0,75 | 0,71 | 21 | |
| w5d3 | `corr_union` | 10 | 0,88 | 0,82 | 38 | |
| w6d4 (popisně) | Kc jádro / uzávěr | 33 / 6 | 0,28 / 0,62 | 0,59 / 0,81 | 22 / 106 | |
| w6d3 (popisně) | Kc jádro / uzávěr | 41 / 15 | 0,55 / 0,68 | 0,39 / 0,83 | 17 / 123 | |
| synt. seed 335 | Kc jádro / uzávěr / B1b | – | F1 0,44 / **0,77** / 0,93 | 0,0 | – | recall jádra 0,29 |

## Předregistrovaná pravidla

- **Test je neinformativní** (8 nálezů kampaně < 10): H3 až H5 se podle předregistrace nehodnotí.
- **H1 platí** (130 shodných zobrazených nálezů). **H2 platí** (0 duplicit v Kc, v1 má 48).
- **H6 neplatí:** uzávěr Kc na syntetice F1 0,769 (potřeba ≥ 0,95); jádro samotné 0,44, protože řetězce závisejí na rolových vazbách.
- Rozhodnutí podle předregistrace: H6 neplatí, uzávěr nenahradí úplnost, **`corr_core` se jako náhrada seskupení nedoporučuje**.

## Popisně napříč dny

Jádro bez rolových vazeb **nepodléhá perkolaci** (největší 5, 17 a 22 nálezů) a má nižší kontaminaci (0,39 až 0,59) než kterékoli plné seskupení (0,89 až 0,95), ale i nižší úplnost (0,28 až 0,55). Uzávěr přes `related` vrací úplnost na 0,62 až 0,75, kontaminace uzávěru je však opět 0,71 až 0,83.

## Co z toho plyne

Ani rozdělení na jádro a odkazy nevyřeší kompromis: čistota jádra se platí úplností a úplnost uzávěru kontaminací. **Žádná z testovaných variant (v1, `corr_v2`, `corr_v3` s `corr_ext` a `corr_related`, `corr_tactic`, `corr_union`, `corr_core`) není na skutečných datech zároveň úplná a čistá.** Souhrnný závěr je v `zaver-korelace.md`.
