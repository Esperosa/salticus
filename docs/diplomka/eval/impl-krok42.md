# Krok 42: `corr_tactic` (řetězení jen mezi nálezy s mapovanou taktikou): zamítnuto

Podklad: `predreg-krok42.md`, kód zmrazen commitem `262474a`. Test: DAPT2021 Week6_Day4_07012021 (156 259 toků, 36 oken, zobrazeno 250 nálezů, z toho 29 kampaně: informativní). Dev: Week6_Day3 (popisně). Regrese: syntetické řetězce seed 335 (použity v kroku 35).

## Výsledek na testu (úroveň normal)

| rameno | incidenty | s kampaní | úplnost | hostů kampaně v nejlepším | kontaminace | největší incident | duplicity |
|---|---|---|---|---|---|---|---|
| v1 (A) | 4 | 3 | (1,0, artefakt duplicit) | 1 | 0,88 | 438 | 335 |
| C | 8 | 3 | 0,72 | 2 | 0,89 | 212 | 0 |
| **Ct** (C + `corr_tactic`) | 25 | 9 | 0,28 | 1 | 0,76 | 43 | 0 |
| U (`corr_union`) | 7 | 4 | 0,83 | 3 | 0,85 | 177 | – |
| B1b (offline) | 2 | 1 | 0,90 | 3 | 0,89 | 240 | – |
| C uzávěr přes `related` | 2 | 2 | 0,79 | 2 | 0,90 | 237 | – |

## Předregistrovaná pravidla (rameno Ct)

- **H1 platí:** zobrazené nálezy beze změny (250 shodných).
- **H2 platí:** 0 duplicitních položek (v1: 335).
- **H3 platí:** největší incident Ct 43 z 250 nálezů (17 %); u C 212 (85 %).
- **H4 neplatí:** kontaminace Ct 0,76 proti 0,89 u C a B1b, rozdíl 0,13 (potřeba ≥ 0,20).
- **H5 neplatí:** hostů kampaně v nejlepším incidentu 1 proti 2 u C a úplnost 0,28 proti 0,72 (potřeba ≥ 0,36).
- **H6 neplatí:** na syntetických řetězcích párové F1 0,889 (potřeba ≥ 0,95; C 0,988); pivot 0,82 a kolize 0,54.

Podle předregistrace: H5 nebo H6 neplatí, takže pravidlo škodí zachycení řetězců a **zamítá se**.

## Co z toho plyne

1. Omezení řetězení na nálezy s taktikou **brání perkolaci** (největší incident z 85 % na 17 %), ale **stejným krokem ztrácí skutečné propojení kampaně**: nálezy kampaně (včetně nespárovaných událostí bez taktiky) se přestanou spojovat a incident kampaně se rozpadne na devět.
2. Dev den (Week6_Day3, popisně): největší incident 17, kontaminace 0,48, úplnost 0,55; stejný obraz (čistší, ale roztříštěný).
3. Souhrn přes všechna skutečná data (LLDOS ×2, PicoDomain, DAPT2021 ×4 dny): **žádný způsob seskupení nedosáhl současně vysoké úplnosti a nízké kontaminace**. Mechanismus, který kampaň propojí (řetězení přes sdílené hosty), je týž, který v podnikové síti propojí všechno; jednoduchá omezení (mez hubu, okno, taktika, četnost adresy) mají vždy cenu v úplnosti.
4. Kód `corr_tactic` zůstává ve výchozím stavu vypnutý a označený jako zamítnutý; mapování `bruteforce_attempts` a `outbound_scan` na taktiku se ponechává (zlepšuje pole `phases`).
5. Jediný stabilní přínos korelace napříč všemi daty je odstranění duplicitních položek ve v1 (až 681 položek v jednom incidentu).

## Další krok

Změnit otázku: místo jednoho velkého seskupení nabízet **více pohledů**: malý jádrový incident z nejsilnějších vazeb (stejný aktér a protějšek, sdílená oběť nálezu bez hosta) a vše ostatní jen jako `related` s důvodem; úplnost se měří uzávěrem, čistota jádrem (krok 43).
