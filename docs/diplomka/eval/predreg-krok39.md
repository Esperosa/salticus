# Předregistrace kroku 39: korelace na PicoDomain (skutečná vícehostitelská APT)

Zapsáno před měřením. Navazuje na `plan-korelace-final.md` (K9) a `impl-krok36.md`.

## Data (nikdy nepoužitá při návrhu pravidel)

PicoDomain (GitHub iHeartGraph/PicoDomain, GPL-3.0): Zeek logy z malé Windows domény 19. až 21. 7. 2019 (JSON, 257 540 toků) a ruční záznam útočných akcí `Red Log.xlsx` (79 akcí, přesnost asi 1 minuta). Kampaň: trojanizovaný archiv, C2 callback na 3.3.3.5, eskalace (Hot Potato, UAC bypass), Mimikatz, enumerace domény, DCOM na HR-WIN7-2, WMI na RND-WIN10-1 a 2, persistence, nakonec persistence na doménovém řadiči. Hostitelé kampaně: 10.99.99.152, .30, .29, .27, .5 (DC) a C2 3.3.3.5. Obsah logů jsem před předregistrací neprohlížel kromě formátu.

Kód zmrazen na commitu **7e2204e** (stav po ); žádné změny pravidel ani prahů před měřením, jediné měření.

## Ramena a metriky

Běhy: A (v1, bez `corr_v2`), C (`corr_v2`+`corr_v3`+`corr_ext`+`corr_related`, finální konfigurace), U (`corr_v2`+`corr_union`). Offline: B1 a B1b (sdílená IP bez a s oknem a mezí hubu) ze zobrazených nálezů běhu C. Okna 30 min, scope 10.99.99.0/24. Úrovně označení nálezu jako kampaň: **loose** (zmiňuje adresu kampaně), **normal** (navíc v časovém intervalu kampaně ±30 min), **strict** (zmiňuje IP hostitele řádku logu a je do 30 min od jeho času). Pro každé rameno a úroveň: počet incidentů s nálezem kampaně, úplnost (podíl nálezů kampaně v nejlepším incidentu), počet hostitelů kampaně v nejlepším incidentu, kontaminace, největší incident; pro C navíc uzávěr přes `related`.

## Hypotézy a pravidla (rameno C, úroveň normal; úroveň strict a loose se uvádí vedle)

- **H1 (bez ztráty):** množina zobrazených `finding_id` v A a C totožná.
- **H2 (propojení hostitelů):** nejlepší incident C obsahuje nálezy aspoň 2 různých hostitelů kampaně (jinak korelace nepropojila ani laterální pohyb).
- **H3 (čistota a hub):** kontaminace samotného incidentu C ≤ 0,25 a největší incident ≤ 20 % zobrazených nálezů (DC je v logu benigní hub i hostitel kampaně).
- **H4 (úplnost uzávěru):** uzávěr přes `related` obsahuje ≥ 0,5 nálezů kampaně a ≥ 3 hostitele kampaně.
- **H5 (proti baseline):** C má nižší kontaminaci než B1b, nebo uzávěr C má vyšší úplnost než B1b při kontaminaci ne vyšší o víc než 0,10.

## Rozhodnutí z výsledku

- H1 až H4 platí: K9 dostává druhou nezávislou kampaň; výchozí profil až po K16.
- H2 nebo H4 neplatí: přínos korelace na skutečných kampaních není prokázán a plán se přeřadí na vážené `related` a další data (Unraveled).
- H3 neplatí: hub nebo slévání, oprava před dalším krokem.
- H5 neplatí: kauzální a související mechanismus nepřináší nic nad jednoduchým seskupením; zapsat jako negativní.

## Omezení

Jedna kampaň; pravda je ruční s přesností 1 minuty a 30minutová okna přehrání zrnitost pravdy zhrubují; stanice a DC mají mnoho benigního provozu, takže označení podle zmínky adresy hostitele je horní odhad. Net: výsledek se hlásí po úrovních, ne jako jedno číslo.
