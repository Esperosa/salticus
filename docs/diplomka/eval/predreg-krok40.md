# Předregistrace kroku 40: korelace na Unraveled/DAPT2021 (APT s pravdou po fázích)

Zapsáno před měřením. Navazuje na `plan-korelace-final.md` (K9) a `predreg-krok39.md`.

## Data

Unraveled/DAPT2021 (veřejný bucket `s3://dapt2021`, bez podpisu): NFStream CSV po snímačích (net1011x až net1015x a netgw) s poli Activity, Stage, DefenderResponse, Signature; datová sada není moje, labely jsou po tocích. Převod `tools/k40_dapt.py convert` (spojení snímačů, odstranění duplicitních toků, Zeek-like `conn.log`). Kampaň = toky se Signature `APT` (adresy a časové intervaly fází z labelů); ostatní útoky (AA, SH) se do kampaně nepočítají a nálezy zmiňující jen jejich adresy se z kontaminace vynechají.

- **Dev:** Week5_Day6_06272021 (63 122 toků, 45 oken) pro odladění skriptu; výsledek je popisný (viz impl-krok40.md).
- **Test:** Week5_Day4_06242021 (54 832 toků), jednou. Před předregistrací jsem z něj četl jen souhrn labelů (adresy a intervaly fází kampaně) potřebný k pravdě.
- Kód zmrazen na commitu **7a6a4a1**, žádné změny pravidel ani prahů před měřením.

## Ramena a úrovně

A (v1), C (`corr_v2`+`corr_v3`+`corr_ext`+`corr_related`), U (`corr_v2`+`corr_union`), offline B1 a B1b, uzávěr C přes `related`. Úrovně nálezu: loose (zmiňuje adresu kampaně), normal (v čase kampaně ±30 min), strict (v intervalu fáze ±30 min). Měřítka: incidenty s nálezem kampaně, úplnost, hostitelé kampaně v nejlepším incidentu, kontaminace, největší incident; duplicitní položky v incidentech (počet položek proti počtu různých nálezů).

## Hypotézy a pravidla (rameno C, úroveň normal)

- **H1:** zobrazené nálezy v A a C totožné.
- **H2 (duplicity):** incidenty ramene C neobsahují opakované `finding_id` (v1 je podle dev dne obsahuje).
- **H3 (propojení):** nejlepší incident C obsahuje nálezy aspoň 2 různých adres kampaně.
- **H4 (čistota):** kontaminace ≤ 0,25 a největší incident ≤ 20 % zobrazených nálezů.
- **H5 (proti baseline):** C má nižší kontaminaci než B1b nebo uzávěr C vyšší úplnost než B1b při kontaminaci ne vyšší o víc než 0,10.

## Omezení

Kampaň má v logu malý počet nálezů (dev den: 10 z 93), všechny adresy jsou privátní (10.0.0.0/8 i 192.168.0.0/24), takže pravidlo vnějšího protějšku (`corr_ext`, jen veřejné adresy) se neuplatní. Stupně fází jsou souvislé přes celý den, proto úrovně normal a strict splývají. Jedna kampaň.
