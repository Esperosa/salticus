# Kroky 36 a 37: korelace na DARPA 2000 LLDOS (nezávislá data) a kompromis úplnost proti čistotě

Podklad: `predreg-krok36.md` (a dodatek se zmrazením). Data: DARPA 2000 LLDOS 1.0 (dev, 125 tisíc toků, 7 oken po 30 min) a LLDOS 2.0.2 (test, 79 tisíc toků, 4 okna), vnitřní tcpdump → Zeek 9.0.1 → `conn.log`. Pravda: `phase-N.list`. Nález patří kampani, jen když zmiňuje adresu kampaně (hrubé; v LLDOS 1.0 je 28 takových nálezů z 50, v 2.0.2 jen 5 z 44). Případová studie, jedna kampaň na dataset, bez statistických testů.

## Zjištění o datech a harnessu

- LLDOS 2.0.2 je z dubna (letní čas UTC-4), 1.0 z března (UTC-5). Můj harness to nejdřív nerozlišil (fázové metriky vyšly nulové); opraven jen vyhodnocovací skript, běhy se neopakovaly, kód v testu je beze změny.
- Stažený pcap LLDOS 2.0.2 končí před fází 4 a 5 (poslední tok 19:36 UTC, fáze 4 začíná 19:41), takže test pokrývá jen fáze 1 až 3; „pokryté fáze“ v tabulce vznikají tolerancí ±30 min. Fáze 5 (záplava DDoS) není v žádném souboru zachycena nálezem.

## Výsledky (rameno = způsob seskupení nálezů; „nejlepší incident“ = ten s nejvíc nálezy kampaně)

| dataset | rameno | incidenty s kampaní | úplnost (podíl nálezů kampaně v nejlepším) | kontaminace | největší incident |
|---|---|---|---|---|---|
| 1.0 dev | v1 (produkce) | 3 | 0,11 | 0,00 | 3 |
| 1.0 dev | `corr_v3` | 3 | 0,11 | 0,00 | 3 |
| 1.0 dev | `corr_v3` + `corr_ext` | 7 | 0,39 | 0,19 | 11 |
| 1.0 dev | `corr_union` | 3 | 0,71 | 0,28 | 30 |
| 1.0 dev | B1 (offline sdílená IP) | 4 | 0,64 | 0,19 | 24 |
| 2.0.2 test | v1 | 0 | 0 | – | 2 |
| 2.0.2 test | `corr_v3` | 0 | 0 | – | 3 |
| 2.0.2 test | `corr_v3` + `corr_ext` | 2 | 0,40 | 0,00 | 4 |
| 2.0.2 test | `corr_union` | 1 | **1,00** | **0,72** | 18 |
| 2.0.2 test | B1b (offline) | 2 | 0,60 | 0,00 | 13 |

## Předregistrovaná pravidla (rameno `corr_v3` + `corr_ext`, test 2.0.2)

- **H1 platí:** zobrazené nálezy v běhu bez korelace a s ní totožné.
- **H2 platí nominálně:** 2 incidenty s kampaní, nejlepší pokrývá fáze 1 až 4 (fáze 4 jen tolerancí ±30 min, data fázi 4 neobsahují); důkaz slabý.
- **H3 platí:** kontaminace 0,00, největší incident 4 z 44 (9 %).
- **H4 neplatí:** `corr_v3`+`corr_ext` nemá nižší kontaminaci ani menší fragmentaci než B1b (obě 0 a 2) a má nižší úplnost (0,40 proti 0,60). Remíza v čistotě, horší v úplnosti.

## Co z toho plyne

1. **Samotné `corr_v3` (kauzální role) na skutečné kampani nic nespojí** (úplnost 0,11 a 0), protože 22 z 28 nálezů kampaně jsou nálezy bez hosta a sdílený je vnější útočník nebo oběť. Syntetická výhoda `corr_v3` (kolizní dvojice) vznikla z mého generátoru a na skutečných datech se neprojevila.
2. **Kompromis, který nelze zadarmo vyřešit:** sdílení adresy (`corr_union`) dává vysokou úplnost (1,00 v 2.0.2), ale i vysokou kontaminaci (0,72: v incidentu o 18 nálezech je jich 13 mimo kampaň, typicky přes server uvedený v pravdě i jako cíl benigního provozu); kauzální pravidla dávají nulovou kontaminaci a nízkou úplnost. Žádná z variant není dominantní.
3. **Hrubé měřítko:** označení nálezu zmínkou adresy kampaně je u busy hosta ve skutečné síti nejednoznačné (časový timeout hostu 172.16.112.100 není nutně útok). Úplnost a kontaminace jsou proto horní a dolní odhady, ne přesná čísla. Přesnější pravda by potřebovala mapování nález → relace pravdy (čas, port).
4. **Krok 36 platí jako negativní výsledek pro hypotézu, že `corr_v3` je lepší než triviální seskupení na skutečných datech.** Kauzální seskupení jako výchozí volbu nedoporučuji.

## Doporučení pro další krok

Neslévat tvrdě. Incident nechat z silných vazeb (stejný aktér a protějšek, kauzální řetěz, stejná oběť s oknem) a nálezy slabě spojené sdílenou adresou nabízet jako související incidenty (`related`), každé s důvodem. Úplnost se pak měří uzávěrem přes související incidenty (blízko `corr_union`) a čistota na samotných incidentech (blízko `corr_v3`+`corr_ext`). To je standardní postup jiných nástrojů (entitní spojování s kontrolovanou šíří), nahrazuje volbu „slévat nebo ne“ a je to další krok.
