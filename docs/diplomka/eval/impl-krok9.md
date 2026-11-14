# Implementace, krok 9: rozšíření pokrytí, provozní incidenty a hloubka ověřování

Datum 2026-11-13. Výchozí stav: krok 8 (`eb27baf`), `recommended()` = sestava kroku 7, `endpoint` mimo preset, výchozí režim `legacy`. Rešerše: `studie/09-open-source-pouceni.md`.

Výchozí čísla (dlouhý běh kroku 7, 7 988 sítí): exploit_attempt 74,6 % (správný typ 42,5 %), c2_beacon 85,5 % (70,4 %), ics_attack 87,2 % (55,6 %), ddos_volume 90,4 %, port_scan_vertical 89,7 %, fleet_beacon 93,5 % (74,3 %). Ostatních 12 rodin má 90 až 98 %.

Poctivost: 100 % se neslibuje. Každé slepé místo je buď (a) uzavřeno měřeným účinkem, (b) zadrženo kódem vynuceným opatřením, nebo (c) uvedeno jako otevřené. Rodina s n < 50 útoků je označena „nedostatek dat“, ne „splněno“.

## A) Rozsah

1. **Rodiny a varianty (generátor).** Nový svět `--coverage k9` (= `k7` + parametrické varianty podle ATT&CK) přidává 72 bezpečnostních variant (`Family::Var`) a 28 provozních poruch a incidentů (`Lookalike::Var`). Varianty jsou data (tabulka vzorů chování: protokol, port, tempo, jitter, objem, topologie, rozprostření zdrojů a času, maskování), ne kód na míru. Emise je jediný obecný generátor syntetických záznamů toků a IDS řádků. Neobsahuje žádný exploit, payload ani nástroj. Ground truth, ID techniky ATT&CK a očekávané typy nálezů jsou součástí tabulky. Bez `--coverage k9` je výstup bajtově beze změny.
2. **Provozní incidenty jako rovnocenná kategorie.** Každá položka pravdy má kategorii: `security`, `ops_fault`, `benign_change`. Provozní řetězce příčina → následek (kaskáda, částečný výpadek, flapping, pomalá degradace, sezónní špička, plánovaná údržba vs. neplánovaný výpadek, falešný výpadek způsobený senzorem) mají společné `incident_id` v pravdě, aby šlo měřit seskupení.
3. **Detekce a ověřování.** Obecné detektory a kontext, ladění jen na ladicích seedech. Žebřík a plánovač nabízejí další nezávislé kontroly při nejistotě (viz C). Vyhodnotí se podíl „potvrzeno / vyvráceno / nerozhodnuto“ a jeho přesnost.
4. **Koncová telemetrie.** Rozhodnutí o zapnutí `endpoint` v `recommended()` se činí jen z měření (práh K9-E).

## B) Předregistrace prahů (zamčeno commitem před prvním měřicím během)

Sekce B se po prvním měřicím běhu nemění. Oprava chyby harnessu se zapíše jako odchylka do sekce D, práh se nemění.

### B1. Seedy a ramena

| účel | seedy | svět | sítí |
|---|---|---|---:|
| ladění | 20261102, 20261103, 20261104, 20262201, 20262202, 20262301, 20262302 | `--coverage k9 --families all` | po 40 (kde to dovolí čas, jinak méně a uvede se skutečný počet) |
| držené, pustit jednou na konci | 20261901, 20262001, 20262101, 20262102, 20261201, 20261301 | totéž | po 40 |

Nepoužije se seed 20261110 (dlouhý běh kroku 8 běží). Ramena: `k8ref` (`recommended()` + `endpoint`, srovnání s krokem 8 na světě `k9`), `k9` (kandidát po úpravách detekce a ověřování). Společné volby: `--no-legs --no-feedback --counterfactual --block-size 2`, nejvýš 4 vlákna, priorita Idle, jedno rameno najednou. Rozhoduje se párově po sítích, bootstrap po sítích (B = 2000), intervaly Wilsonovy.

### B2. Prahy bezpečnostních rodin (každá rodina, každá varianta s n ≥ 50)

| práh | definice | splněno, když |
|---|---|---|
| K9-1 | detekce rodiny | ≥ 90 % a dolní mez Wilsonova 95% intervalu ≥ 85 % (cíl 95 %) |
| K9-2 | správný typ nálezu | ≥ 85 % a dolní mez ≥ 80 % (u rodin s typovanými nálezy) |
| K9-3 | zobrazené FP na síť-den a všechny zobrazené položky | ≤ 1,15 × krok 8 na stejném světě |
| K9-4 | zavřeno omylem | ≤ 2,2 % |
| K9-5 | chráněná automatická zavření | 0 |
| K9-6 | determinismus a kompatibilita | stejný seed dvakrát bit po bitu; legacy a stávající v3 bez nových přepínačů bajtově beze změny; golden snapshot zelený |
| K9-7 | paniky a porušené invarianty | 0 |
| K9-8 | velikost vzorku | n ≥ 50 útoků na rodinu, jinak „nedostatek dat“ (nepočítá se jako splněno ani jako nesplněno) |

### B3. Prahy provozních incidentů (zvlášť, každá rodina poruch s n ≥ 50)

| práh | definice | splněno, když |
|---|---|---|
| O1 | detekce poruchy (nález připsaný incidentu v okně +2 cykly) | ≥ 90 %, dolní mez ≥ 85 % |
| O2 | správná klasifikace (bezpečnostní / provozní / neškodná změna / nerozhodnuto), správná = shoda s kategorií pravdy, `nerozhodnuto` se počítá zvlášť a nepočítá se jako správné | ≥ 85 % |
| O3 | seskupení: počet incidentů na pravdivý incident (cíl 1) a čistota (podíl nálezů incidentu, které patří jeho pravdě) | poměr nálezů k incidentům aspoň 3:1 u poruch s ≥ 3 nálezy a čistota ≥ 90 % |
| O4 | čas do prvního nálezu | medián ≤ 2 cykly od začátku, 90. percentil ≤ 6 cyklů |
| O5 | FP provozních incidentů (zobrazený incident bez pravdy) | ≤ 1,15 × krok 8 |
| O6 | prázdná telemetrie nikdy neznamená „v pořádku“ | výpadek senzoru nikdy nezavře ani nevyvrátí nález (invariantní test) |
| O7 | záměna | poruchy označené jako bezpečnostní ≤ 15 %, bezpečnostní označené jako porucha a zavřené ≤ 2,2 % |

Klasifikace a seskupení do incidentu je v době předregistrace v jádře jen částečně (třída provoz, kontext). Pokud se nepodaří implementovat, práh O2, O3 a O7 se uvede jako nesplněný (kategorie c) a změna prahu se nepovolí.

### B4. Ověřování a kalibrace

| práh | definice | splněno, když |
|---|---|---|
| V1 | při nejistotě se nález neuzavírá: podíl nálezů se stavem `nerozhodnuto`, který skončil zavřený bez důkazu | 0 |
| V2 | zavřeno omylem (útok s omylem zavřeným nálezem) | ≤ 2,2 % a ≤ krok 8 + 1 % |
| V3 | kalibrace: pravděpodobnost „potvrzeno“ vs. skutečnost, chyba kalibrace (ECE) | ≤ 0,10 (jen pokud je ≥ 200 uzavřených případů, jinak „nedostatek dat“) |
| V4 | přesnost „potvrzeno“ a „vyvráceno“ (podíl správných) | uvede se s intervalem, bez cílové hodnoty |
| V5 | rozpočet: žádná další kontrola nad rámec rozpočtu cyklu | 0 překročení |

### B5. Koncová telemetrie

`endpoint` se zapne v `recommended()` jen když na světě `k9` platí: detekce `on100` − `off` ≥ +3 p. b., FP poměr ≤ 1,10, omylem zavřeno `comp-ok` ≤ `off` + 1 % útoků, 0 chráněných zavření. Jinak zůstává mimo preset. Měření je simulované (generátor vychází z těch samých rodin), proto rozhodnutí je „připraveno na držený běh“, ne „zapnuto jako výchozí“.

## C) Návrh

### C1. Generátor (`src/soak/variants.rs`)

- `VariantSpec`: id, popis, ATT&CK ID (jen číslo a název techniky), kategorie, vzor (`Pattern`), směr, protokol, port nebo sada portů, základní tempo na cyklus, jitter, objem, doba trvání v cyklech, počet zdrojů, maskování do legitimního provozu, příznak IDS.
- Vzory: `Periodic` (maják s jitterem), `Burst`, `Sweep` (horizontální), `PortSweep` (vertikální), `Flood`, `Sustained` (dlouhé spojení), `FanOut`, `FailedAuth` (série neúspěšných přihlášení), `BulkOut` (objem ven), `Trickle` (nízkoobjemový únik).
- Provozní vzory: `Outage`, `Flap`, `Degrade`, `Storm`, `Saturate`, `TimeDrift`, `PlannedWindow`, `SensorFalse`, `Cascade`.
- Vlastní proud náhody a vlastní větev plánu, takže ostatní světy zůstanou bajtově stejné.

### C2. Realističtější provoz

Denní a týdenní vzory a svátky už jsou. Doplní se dlouhý ocas služeb, zálohy v noci, aktualizace, CDN churn a sezónnost jako parametry světa `k9`, kalibrované na veřejných datech (CIC-IDS2017, CTU-13, IoT-23, UNSW-NB15). Licence a podmínky se zapíší do `dataset-registry.md`. Labely datasetů se nemíchají do jednoho schématu. Kde simulace realistická není, uvede se v sekci E.

### C3. Detekce a ověřování

Obecné detektory a kontext (ne pravidla na míru). Ověřovací žebřík a plánovač: pivot na DNS/TLS/JA3/časování, GeoIP/ASN, srovnání s baseline hostu a peerů, koncová telemetrie, historie případu, opakované měření v čase, aktivní čtecí ověření v povoleném rozsahu. Případ se neuzavírá ani nezahazuje, dokud není překročen práh jistoty nebo vyčerpán rozpočet.

## D) Průběh a odchylky

Datum 2026-11-14. Tabulky: `k9/vysledky.md` (ladicí seedy, před a po po rodinách s Wilsonovými intervaly), `k9/endpoint.md` (koncová telemetrie zapnuto proti vypnuto), `k9/pokryti.md` (technika → rodina → detektor → výsledek), `k9/held.md` (držené seedy, jednou), `k9/datasety.md`, `k9/realismus.md`. Přepočet jedním příkazem: `python tools/k9_finish.py`.

### Co se implementovalo

| blok | soubory | co |
|---|---|---|
| svět `k9` | `src/soak/variants.rs`, `coverage.rs`, `traffic.rs` | 113 parametrických variant (72 bezpečnostních podle ATT&CK, 28 provozních poruch a incidentů a neškodné změny) s kategorií a ID techniky; `salticus-program soak families` vypisuje tabulku (včetně taktiky, tempa, objemu, topologie) |
| obecné detektory | `src/behavior/breadth.rs`, přepínače `breadth`, `breadth_volume` | `broadcast_storm`, `slow_egress` (kumulace pomalého úniku, jen zralý host), a volitelně `ingest_volume_anomaly`, `link_saturation`; žádný nezná rodinu; kontext záloh a oken údržby je pokrývá |
| třída provoz | `src/ops_evidence.rs` | `broadcast_storm` jde do fronty provoz jako E2 (nikdy se nezavírá) |
| ověřování | `src/verification_chain.rs` | řetěz 12 nezávislých kontrol (DNS, TLS a JA3, časování, GeoIP a ASN, baseline hosta, peery, koncová telemetrie, historie případu, reputace, konfigurační kontext, opakované měření, aktivní čtecí ověření); bez dat nulová váha; „vyvráceno“ jen ze dvou skupin a nikdy u chráněného případu; vyčerpaný rozpočet = nerozhodnuto |
| zpětná vazba | `src/analyst_feedback.rs`, `server.rs` | viz `impl-krok10.md` |
| nástroje | `tools/soak_k9.py`, `k9_final.py`, `k9_finish.py`, `k9_coverage_table.py`, `k9_cmp.py`, `datasets/luflow_to_zeek.py` | vyhodnocení, tabulky, převod LUFlow pro přehrání |

### Měření na ladicích seedech

Svět `k9`, 40 sítí na seed, `--engine v3` s presetem kroku 7 a `--endpoint on`, `--no-legs --no-feedback --counterfactual`. Základ `k8ref` (jádro kroku 8), kandidát = základ + `--v3-on breadth`. Přesná čísla jsou v `k9/vysledky.md`; stav tabulky odpovídá seedům, které doběhly (viz její hlavička).

Postup ladění (poctivý záznam, měřeno vždy na ladicím seedu 20261102):

| rameno | změna | detekce | FP / síť-den | výsledek |
|---|---|---:|---:|---|
| `k8ref` | základ | 83,4 % | 8,27 | |
| `b1` | všechny čtyři detektory `breadth` | 86,0 % | 14,17 | FP × 1,71, neprošlo |
| `b3` | zralost hosta, mez střední objem pomalého úniku, aktér linky jen při podílu ≥ 50 % | 84,8 % | 11,88 | FP × 1,44, neprošlo |
| `b4` | kontext záloh a údržby pro nové typy | 84,8 % | 11,91 | bez účinku na FP |
| `b5ops` | + `ops_class`, `ops_annotate` | 84,6 % | 11,70 | třída provoz nepomáhá (jako v kroku 7) |
| `c8` | `breadth_volume` vypnuto (objemové detektory jen volitelně) | 84,5 % (3 seedy) | 9,05 (× 1,04) | **prošlo K9-3**, kandidát |

Důvod rozdělení: `ingest_volume_anomaly` a `link_saturation` přidaly kolem 3,4 zobrazených FP na síť-den (aktualizace, zálohy a migrace do cloudu mají stejný tvar jako stahování dat a hromadný únik) a část jejich „zisku“ byla náhodná atribuce (nález uváděl více hostů). Bez obsahu spojení (reputace cíle, SNI, DNS) je odlišit nelze; zůstávají volitelné (`--v3-on breadth,breadth_volume`) a jsou v registru jako (b).

### Odchylky od předregistrace

1. Rodiny s n < 50 jsou uvedeny s detekcí, ale ve stavu „nedostatek dat“; na úrovni jednotlivých variant dosáhlo n ≥ 50 jen několik rodin ani při několika seedech, proto jsou prahy vyhodnocené i na úrovni vzorů chování, taktik a kategorií (tabulky v `k9/vysledky.md`).
2. Počet nálezů na incident (O3), čistota seskupení a první nález (O4) se neměřily: generátor nenese společný `incident_id` mezi nálezy téže poruchy a jádro nálezy poruch do incidentů neseskupuje (kromě incidentu grafu). Prahy O3 a O4 jsou proto nesplněné (kategorie c); změna prahu se nepovolila.
3. Kalibrace posteriorů žebříku (V3, ECE) se z výstupu soaku nedá odvodit (neukládá posterior případu); neměřeno.
4. Přehrání veřejných datasetů (LUFlow) je jen kontrola průchodu produkční cestou, ne důkaz detekce (viz `k9/datasety.md`).

## E) Registr slepých míst a nerealistických částí simulace

Kategorie: (a) uzavřeno měřeným účinkem, (b) zadrženo opatřením vynuceným kódem nebo zmírněno, (c) otevřené. Seznam rodin pod prahem s n ≥ 50 je v `k9/vysledky.md` (sekce „Rodiny pod prahem“); zde jsou příčiny.

| slepé místo | stav | kategorie |
|---|---|---|
| broadcast a multicast bouře | detekce výrazně nahoře (z 14 na 30 % u vzoru Storm), zbytek jsou nízké intenzity pod `storm_min` | (b) |
| pomalý únik (Trickle, tempo `trickle`) | detekce 63 → 69 %, typ 31 → 54 % | (b) |
| hromadné stahování a odesílání (BulkIn, BulkOut) | `breadth_volume` zvedá detekci o 10 až 14 p. b., ale za cenu FP × 1,44 | (b) volitelné |
| rodiny odlišné od legitimního provozu jen obsahem (DNS, TLS, cloudové logy; viz `CONTENT_ONLY` v `tools/k9_final.py`) | v tocích nerozlišitelné; vyžadují DNS a TLS záznamy | (c) |
| exploit_attempt, c2_beacon, port_scan_*, cryptomining, credential_stuffing | 85 až 90 %; příčina nebyla rozebrána po jednotlivých útocích (u části zmeškaných útoků engine nevydal žádný nález, u zbytku byl nález v kontrafaktuálním světě také přítomen); nezávislé na intenzitě a tempu, bez vazby na IDS | (c) |
| ics_attack | v ladicích seedech bez průmyslových sítí nepokryto | (c) nepokryto |
| incidenty a seskupení poruch (O3, O4), klasifikace bezpečnostní/provozní (O2, O7) | `ops_class` nepomáhá, seskupení v jádře není | (c) |
| koncová telemetrie v `recommended()` | viz `k9/endpoint.md` a rozhodnutí níže | podle práhu B5 |
| nerealistické části simulace | `k9/realismus.md` | |

### Rozhodnutí o koncové telemetrii (B5)

Práh: detekce `on` − `off` ≥ +3 p. b., FP poměr ≤ 1,10, omylem zavřeno `on` ≤ `off` + 1 % útoků, 0 chráněných zavření. Měření (`k9/endpoint.md`, seedy 20261102 až 20261104, 120 sítí): detekce 82,5 → 85,0 % (+2,5 p. b.), FP poměr 1,043, omylem zavřeno 0,9 → 0,8 %, chráněných zavření 0. **Práh na detekci (+3 p. b.) není splněn, proto `endpoint` zůstává mimo `recommended()`.** Omezení měření: rameno `off` a `on` nejsou tytéž binárky na všech seedech (`b6noep`/`b4` na 20261102, `c9off`/`c8` na 20261103 a 20261104), takže rozdíl zahrnuje i drobné rozdíly kódu mezi nimi; měření je navíc simulované.

### Výsledek držených seedů (jednou)

Držené seedy 20261901, 20262001, 20262101, 20262102, 20261201, 20261301, 240 sítí, `heldref` (krok 8) proti `heldc` (kandidát `breadth`), vše v `k9/held.md`.

| práh | předregistrováno | držené seedy | stav |
|---|---|---|---|
| K9-3 FP na síť-den | ≤ 1,15 × krok 8 | 20,38 → 21,58, poměr 1,059 (1,042 až 1,083) | splněno |
| K9-3 všechny zobrazené položky | ≤ 1,15 × | poměr 1,027 | splněno |
| K9-4 zavřeno omylem | ≤ 2,2 % | 0,4 → 0,5 % | splněno |
| K9-5 chráněná zavření | 0 | 0 | splněno |
| K9-7 paniky a invarianty | 0 | 0 / 0 | splněno |
| detekce útoků celkem | (bez prahu) | 83,4 → 84,0 % | +0,6 p. b. |
| K9-1 detekce rodiny ≥ 90 % (dolní mez ≥ 85 %) | každá rodina n ≥ 50 | 41 splněno, 75 pod prahem, 9 nedostatek dat | **nesplněno** (kategorie c/b) |
| K9-6 determinismus | stejný seed dvakrát | v tomto vyhodnocení neověřeno | viz jednotkové testy |

Rozhodnutí o `breadth` v `recommended()`: bezpečnostní prahy (K9-3 až K9-5, K9-7) prošly i na držených seedech, přínos je ale malý (+0,6 p. b.; na ladicích +0,5 p. b.) a K9-1 zůstává z velké části nesplněno. Doporučení: zapnout `breadth` (bez `breadth_volume`) lze, nepoškozuje bezpečnostní prahy; nepovažovat to za splnění K9-1. Kód `recommended()` tímto commitem změněn není.

### Návrh dalšího dlouhého běhu

```
salticus-program soak run --out F:\Projektyakula-soak
un-mega-k9 --seed 20262501 --wall-hours 96 --threads 6 --block-size 4 --engine v3 --coverage k10 --endpoint on --endpoint-coverage 60 --v3-on breadth --noise-mix 1:0.6,10:0.3,50:0.1 --xxxl-share 0.015 --cf-share 0.2 --families all
```
