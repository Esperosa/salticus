# Závěr: korelace nálezů do incidentů (kroky 33 až 43)

## Co je prokázané

1. **Produkční seskupení (v1) mělo prokazatelné vady:** čas události byl čas běhu, nálezy bez hostitele se zahazovaly (u skutečných kampaní 22 z 28 nálezů), stejný nález se do incidentu opakoval při každém zobrazení (v jednom incidentu až 681 položek z 347 nálezů, na každém ze čtyř dnů DAPT2021 stovky duplicit), ořez ponechával nejstarší incidenty, stav byl jeden JSON blob. Opravené chování (`corr_v2`): jedna událost na nález, čas nálezu, stabilní klíč, perzistence po událostech, ořez nejnovějších, souhrn dne, důvody hran. **Toto je jediný přínos prokázaný na všech datech.**
2. **Zachycení se korelací nemění**: v každém měření (syntetika, domácí síť, LLDOS ×2, PicoDomain, DAPT2021 ×4) jsou zobrazené nálezy před korelací a po ní totožné; korelace jen anotuje.
3. Na domácí síti vychází 7,7 incidentů za den a největší incident 5,7 % zobrazených nálezů; výkon 0,2 s CPU na 50 000 událostí.

## Co se neprokázalo

**Žádné seskupení není na skutečných kampaních zároveň úplné a čisté.** Měřeno na 7 skutečných datových celcích (LLDOS 1.0, 2.0.2, PicoDomain, čtyři dny DAPT2021):

| varianta | úplnost | kontaminace | největší incident | poznámka |
|---|---|---|---|---|
| v1 | nízká | 0 až 0,95 | až 85 % | duplicity |
| `corr_v3` (+ `corr_ext`, `corr_related`) | 0,38 až 0,75 | 0,44 až 0,91 | 43 až 85 % | v podnikové síti perkoluje |
| `corr_tactic` | 0,28 | 0,76 | 17 % | rozbije propojení kampaně, zamítnuto |
| `corr_union` / B1b | 0,42 až 1,00 | 0,28 až 0,89 | 29 až 76 % | slévá |
| `corr_core` jádro | 0,28 až 0,55 | 0,39 až 0,59 | 5 až 22 | čisté, ale roztříštěné |
| `corr_core` uzávěr | 0,62 až 0,75 | 0,71 až 0,83 | 21 až 123 | |

Syntetické řetězce kauzální pravidla zvýhodňují (F1 0,99 proti 0,93), ale to je vlastnost mého generátoru; na skutečných datech tento náskok nenastal. Kauzální pravidla se nedoporučují jako výchozí.

## Doporučení

- **Výchozí profil:** korelaci nezapínat; platí kritéria v `stav-plan-korelace.md`.
- **Pokud se zapne:** pro domácí a malé sítě `corr_v2` + `corr_v3` + `corr_ext` + `corr_related` (shadow konfigurace); pro velké sítě `corr_v2` + `corr_v3` + `corr_core` + `corr_related` (bez perkolace, s nižší úplností a odkazy). Obě volby jsou za přepínači a jejich užitečnost pro analytika není ověřena.
- **Opravy bez přepínače jsou v produkčním seskupení výhodné samy o sobě** (duplicity, čas, ořez, perzistence); jejich zapnutí jako výchozí chování je vhodné po 14denním soaku.

## Meze

Čtyři dny DAPT2021 jsou jedna kampaň v jedné testbed síti, takže nejde o čtyři nezávislé kampaně; kampaně LLDOS a PicoDomain jsou jedna kampaň každá. Označení nálezu jako patřícího kampani podle zmínky její adresy je hrubé, zejména v malých sítích; kontaminace je proto nejistá a hlásí se po úrovních. Pravda je po tocích, nikoli po nálezech. Užitečnost pro analytika se bez analytika neprokáže; 14denní soak neproběhl.

## Co by změnilo závěr

Označená vícefázová data z jiné než testbed sítě s nálezy na úrovni, kde nejde o IP-sdílení; kombinace sdílení adresy s dalšími rysy (podobnost chování, shoda času, shoda služby), nikoli s dalším omezením téže vazby; skutečný provoz analytika (K16 a zpětná vazba).
