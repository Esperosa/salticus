# Krok 39: korelace na PicoDomain (nezávislá skutečná APT kampaň) a negativní pokus o omezení `related`

Podklad: `predreg-krok39.md`, kód zmrazen commitem `7e2204e`. Data: PicoDomain (GitHub iHeartGraph/PicoDomain): 257 540 toků ze 3 dnů malé Windows domény, 79 ručně zapsaných útočných akcí (přesnost ~1 min). Kampaň: C2 callback na 3.3.3.5, eskalace, Mimikatz, enumerace domény, DCOM a WMI pivot přes čtyři stanice, nakonec persistence na doménovém řadiči (5 hostitelů + C2). 129 oken po 30 min, 0 selhání. Zobrazeno jen 51 nálezů za 3 dny (tichá síť).

## Výsledek (rameno C = `corr_v2`+`corr_v3`+`corr_ext`+`corr_related`; úroveň označení nálezu: loose 48, normal 26, strict 18 nálezů)

| úroveň | rameno | incidenty s kampaní | úplnost | hostů kampaně v nejlepším | kontaminace | největší incident |
|---|---|---|---|---|---|---|
| normal | v1 (A) | 1 | 0,19 | 4 | 0,00 | 5 |
| normal | C | 5 | 0,38 | 5 | 0,44 | 22 |
| normal | C uzávěr přes `related` | 3 | 0,46 | 5 | 0,47 | 26 |
| normal | B1b offline | 3 | 0,46 | 5 | 0,49 | 30 |
| normal | `corr_union` (U) | 3 | 0,46 | 5 | 0,48 | 29 |
| normal | B1 offline | 1 | 1,00 | 5 | 0,49 | 51 |
| loose | C | 6 | 0,46 | – | 0,02 | 22 |

## Předregistrovaná pravidla (úroveň normal)

- **H1 platí:** zobrazené nálezy beze změny (51 shodných).
- **H2 platí:** nejlepší incident obsahuje 5 hostitelů kampaně (laterální pohyb propojen).
- **H3 neplatí:** kontaminace 0,44 (strop 0,25) a největší incident 22 z 51 (43 %, strop 20 %).
- **H4 neplatí:** úplnost uzávěru 0,46 (potřeba ≥ 0,5; hostů je 5 ≥ 3).
- **H5 platí těsně:** kontaminace C 0,44 proti B1b 0,49; úplnost uzávěru je shodná (0,46).

## Co z toho plyne

1. Na skutečné vícehostitelské kampani **finální konfigurace spojí všechny hostitele kampaně do jednoho incidentu, ale přiřazuje i mnoho nálezů mimo ni** (kontaminace 0,44 podle úrovně normal; podle úrovně loose 0,02). Rozdíl mezi úrovněmi ukazuje, že v šestihostitelské doméně se téměř každý nález týká hostitele kampaně, takže označení podle času je hrubé a kontaminace je velmi nejistá. Úroveň loose je horní odhad čistoty, úroveň normal dolní.
2. **Nad jednoduchým seskupením podle IP (B1b, `corr_union`) finální konfigurace nemá znatelný přínos:** úplnost 0,38 až 0,46 proti 0,46, kontaminace 0,44 proti 0,49. Produkční v1 dává malý čistý incident (5 nálezů, 4 hostitelé, kontaminace 0), ale úplnost jen 0,19.
3. **Přínos nad v1 je v úplnosti** (0,19 → 0,38 až 0,46) za cenu kontaminace; nad B1b žádný. Souhrn přes LLDOS 1.0, 2.0.2 a PicoDomain: žádné z kauzálních pravidel není na skutečných kampaních prokazatelně lepší než jednoduché seskupení s oknem a mezí hubu; hlavní hodnota opravené korelace je v opravách (čas nálezu, nálezy bez hosta, hub, perzistence, stabilní klíč), ne v kauzálních pravidlech.

## Negativní pokus: omezení `related` podle četnosti adresy

Z návrhu nezávislého posuzovatele: adresa ve víc než 3 incidentech je hub a `related` nevytváří. Vyzkoušeno na LLDOS (popisně, data již použitá): úplnost uzávěru klesla z 0,71 na 0,39 (1.0) a z 0,80 na 0,40 (2.0.2), kontaminace zůstala 0,28 a 0,71. Útočník kampaně je sdílený mnoha incidenty, takže ho pravidlo označilo za hub. Změna vrácena, nezapojena. Negativní výsledek: jednoduché omezení podle četnosti adresy nerozliší hub od útočníka; k rozlišení by byla potřeba role adresy (server vs. klient) nebo skóre s časem.

## Další krok

Rozhodnout se podle K16 (14denní soak) a dalších skutečných kampaní (Unraveled). Do té doby jsou `corr_*` přepínače jen v shadow konfiguraci, výchozí profil se nemění.
