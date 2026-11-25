# Plán korelace v2 (návrh k připomínkám)

Stav k 25. 11. 2026. Nahrazuje tabulku kroků v `plan-korelace.md` §2, ostatní části té zprávy platí. Cíl: korelace, která je prokazatelně lepší než triviální seskupení, nic nezavírá a neskrývá, a v provozu dává analytikovi souvislé incidenty místo roztříštěných nálezů.

## 1. Co je změřeno

- Produkční v1 má na vícefázových řetězcích F1 0,26 (úplnost 0,16), seskupení podle sdílené IP 0,78. `corr_v2` 0,0. `corr_v3` 0,93 (interval 0,88 až 0,98), slité kolizní dvojice 5 z 10 (B1: 10 z 10). Zobrazené nálezy beze změny.
- Šum pozadí: 24 incidentů za 3 dny z domácí sítě a 45 z řetězců; strop 45 celkem neplatí.
- Meze: řetězce jsou syntetické a `corr_v3` odpovídá jejich tvaru; žádné měření na skutečných označených datech; nález skenu nemá zdroj; bootstrap má 30 jednotek.

## 2. Zbývající kroky

| # | krok | kritérium hotovo | typ |
|---|---|---|---|
| K9 | `corr_v3` na skutečných označených datech (CTU-13 dev 42/51/54, test ostatní; IoT-23): host = řetěz, fáze podle štítků | předregistrace; bez ztráty zachycení, největší incident ≤ 20 % nálezů scénáře, počet incidentů na infikovaný host | měření |
| K10 | Šum pozadí: proč vznikají incidenty typu interactive_session + long_lived_tunnel jednoho hosta; rozhodnutí, zda jsou to incidenty | 3denní domácí běh: ≤ 15 incidentů/den, každý s důvodem; bez ladění na pravdě | měření + úprava |
| K11 | Důvod spojení na každé hraně incidentu (`links[].reason`) a zobrazení v případové složce | žádná hrana bez důvodu (test), vysvětlení čitelné bez kódu | kód |
| K12 | Zdroj skenu v `unmapped_passive_event` (nesou jen oběť): zjistit, zda lze zdroj doplnit z toků bez změny detekce | slité kolizní dvojice z 5 na ≤ 2 z 10, zachycení beze změny | kód + měření |
| K13 | Persistence korelace po událostech místo jednoho JSON, idempotence okna, stabilní klíč incidentu | opakování okna = shodný výstup; 20 přerušení = 0 duplicit a 0 ztrát; zápis ≤ 1 MB/okno | kód + test |
| K14 | Ovládání incidentu: sloučit, rozdělit, nespojovat (audit, nikdy změna závažnosti ani zavření) | přežije restart a retenci | kód |
| K15 | Degradace a zdroje: chybějící zdroj hlásí `coverage_gaps`; výkon na 50 000 událostech | ≤ 2 s CPU, ≤ 150 MB; běh nespadne | kód + měření |
| K16 | Shadow soak 14 dní se zapnutou korelací na domácí síti | stabilita počtu incidentů (týden 1 vs. 2 ±25 %), 0 nálezů znovu zobrazených kvůli nestabilnímu klíči, 0 uzavřených chráněných | provoz |
| K17 | Rozhodnutí o výchozím profilu (council) | podle K9 až K16 | rozhodnutí |

Pořadí: K9 a K10 nejdřív (rozhodují, zda `corr_v3` vůbec stojí za provoz), pak K11, K12, K13 (nezávislé), K14, K15, K16, K17.

## 3. Definice „prokazatelně splněno“

1. Všechna kritéria K9 až K16 splněna s dokumentem kroku, předregistrací před měřením a nepoužitými seedy pro test.
2. Nezávislé review po kroku, který sahá na stav, souběh nebo rozhodování (jeden nezávislý posuzovatel, jen čtení).
3. 0 uzavřených chráněných nálezů a 0 změn zobrazení způsobených korelací (H1 v každém měření).
4. Negativní výsledky zapsané; žádné ladění prahů na testovacích datech; změna prahu = nový krok s novým seedem.
5. `cargo test --lib` pro dotčené moduly, `cargo fmt`, README stav, commit a push po každém kroku.

## 4. Rizika

- K9 může `corr_v3` vyvrátit (skutečné botnety nemají kauzální řetězy, jen jeden host); pak se přiznává, že přínos je omezen na vícefázové průniky.
- K12 může narazit na to, že zdroj skenu v datech není; pak zůstává omezením.
- K16 trvá 14 dní reálného času.
- Úzká metrika (F1 přes dvojice) může vybírat to, co generátor dává; proto K9 na cizích datech.
