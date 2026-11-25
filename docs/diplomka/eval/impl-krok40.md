# Krok 40: Unraveled/DAPT2021 (APT s pravdou po fázích na úrovni toků)

Podklad: `predreg-krok40.md`, kód zmrazen commitem `7a6a4a1`. Data: veřejný bucket `s3://dapt2021`, NFStream CSV (net1011x až net1015x, netgw) s labely Activity, Stage, Signature. Dev: Week5_Day6_06272021 (63 122 toků po odstranění duplicit, 45 oken), test: Week5_Day4_06242021 (54 832 toků, 49 oken), jednou.

## Výsledek

**Dev (popisně):** zobrazeno 93 nálezů, z toho 10 zmiňuje adresy kampaně APT (fáze Establish Foothold, Data Exfiltration, Lateral Movement; hostitelé 10.1.3.8, 10.1.3.17, 192.168.0.11, 10.8.10.84). Produkční v1 vytvořila incident o 272 položkách z 93 nálezů (stejné nálezy opakovaně), úplnost vyšla > 1, což je artefakt duplicit; `corr_v2`+`corr_v3`+`corr_ext`+`corr_related` má nejlepší incident s 7 nálezy kampaně (úplnost 0,70, kontaminace 0,61, největší incident 18); `corr_union` a B1b úplnost 0,70 a kontaminaci 0,68.

**Test (jednou):** zobrazeno jen **7 nálezů, z toho 1 týkající se kampaně**. Rameno C nevytvořilo žádný incident, A tři (11 duplicitních položek), U jeden.

## Předregistrovaná pravidla (rameno C, úroveň normal)

- **H1 platí:** zobrazené nálezy v A a C totožné.
- **H2 platí:** C 0 duplicitních položek v incidentech, v1 (A) 11 (na dev dni 179 duplicit).
- **H3 neplatí:** nejlepší incident C neexistuje (0 incidentů).
- **H4 nelze posoudit** (žádný incident s kampaní; kontaminace 0 bez významu).
- **H5 nelze posoudit.**

## Co z toho plyne

1. Test je pro měření korelace **nepoužitelný**: kampaň APT je v těchto datech nízkoobjemová (stovky toků mezi vnitřními hostiteli) a Salticus na ni zobrazí jen jediný nález za den. To je spíš mez detekce (pozdní fáze nízkého objemu mezi privátními adresami) než problém seskupování. Korelace nemá co spojovat.
2. Skutečným výsledkem kroku je **potvrzení vady v1**: produkční seskupení opakuje stejné nálezy v incidentu (až 272 položek z 93 nálezů). Oprava (`corr_v2`: jedna událost na nález) tuto vadu odstraňuje a je to jediný přínos korelace, který se dosud prokázal na všech skutečných datech (LLDOS, PicoDomain, DAPT2021).
3. Pravidlo vnějšího protějšku (`corr_ext`) se tu neuplatní: v testbedu jsou všechny adresy privátní, útočník je ve stejném bloku 10.0.0.0/8.
4. K9 nezíská z tohoto dne další pozitivní ani negativní důkaz o kauzálních pravidlech. Zbývají dny s větším objemem (Week6_Day3, 203 MB) nebo jiné sady; do rozhodnutí o výchozím profilu je to nedodělek, ne překážka.
