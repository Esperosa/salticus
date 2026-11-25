# Plán korelace, finální verze (po debatě čtyř agentů)

Vznikl ve dvou kolech: tři nezávislé rozbory (architekt, skeptik a metrolog, pragmatik provozu), pak připomínky ke konkrétnímu návrhu (`plan-korelace-v2.md`) od těch tří plus čtvrtého, adversariálního oponenta na Opusu, který četl i kód. Nahrazuje `plan-korelace.md` §2 a `plan-korelace-v2.md` §2 až §3. Stav: kroky K1 až K5 hotové (`impl-krok34.md`), zbytek je tento plán.

## 1. Co debata změnila

Ověřeno v kódu (ne jen tvrzeno):

- Ořez `truncate(MAX_INCIDENTS)` po řazení vzestupně podle `first_ts` ponechá **nejstarších** 200 incidentů, nové zahodí (`retro.rs:320`, `correlation_layer.rs:323`). Skutečná chyba, kterou jsem v krocích 33 až 34 nezachytil.
- Čítač stupně klíče v `incidents_v3` nikdy neklesá (`retro.rs:236`): infikovaný host s víc než 25 nálezy přestane spojovat a incident se rozpadne. Ohrožuje K9.
- `has_finding` je lineární přes celou historii a událost se po prvním zápisu nikdy neaktualizuje o nové důkazy (`retro.rs:114`, `correlation_layer.rs:201`).
- Pravidlo (c) spojuje nálezy bez hosta na stejné oběti a každý nález s touto obětí jako protějškem se pak připojí k nim; to je spojení přes sdílený protějšek přes mezilehlý uzel, ne jen limit chybějícího zdroje skenu.

Metodika kroku 34 má slabiny, které jsem přiznal jen částečně: pravidla i generátor jsou od stejného autora (seed 233 ověřuje nové instance téhož tvaru, ne nezávislost); B1 je slabá baseline (tranzitivní bez okna a bez meze hubu); metrika nevidí, když se řetězec slije s nálezy pozadí; přiřazení nálezu k řetězci podle IP je s pravidly kruhové; H2 jsem po neúspěchu nepřeformuloval správně: předregistrace říkala „oprava před čímkoli dalším“, já jsem pokračoval. **Platí se zpětně:** výsledek kroku 34 je „na syntetickém tvaru A→V→X je `corr_v3` lepší než seskupení podle IP bez okna“, nic víc.

## 2. Rozhodnuté neshody

| otázka | rozhodnutí |
|---|---|
| Entitní graf hned? | Ne (architekt i skeptik). Až po K9, pokud hrany „host = řetěz“ nestačí. |
| Zdroj skenu (K12) hned? | Až po opravě pravidla (c) a přeměření; pokud po ní zůstanou slité dvojice, K12 se udělá s polem `srcs` mimo `finding_id` (architekt, `anomaly.rs:18-34`). Pragmatik ho chtěl škrtnout, Opus ukázal, že část slévání je chyba pravidla; proto nejdřív oprava. |
| Rozhodnutí o výchozím profilu radou (council)? | Ne. Číselná tabulka kritérií, předem daná (pragmatik, Opus). Council jen pro review kódu. |
| Strop „největší incident ≤ 20 %“ | Škrtnuto pro jednohostové botnety (architekt); nahrazeno čistotou podle štítků. |
| Soak ±25 % týden 1 vs. 2 | Nahrazeno mediánem a rozptylem denních počtů plus absolutním stropem (pragmatik, architekt). |
| Zapnout `case_files`/`corr_v3` dřív? | Ne dřív než po K9 a K10 (skeptik, pragmatik). V1 je horší než triviální seskupení, ale přepnutí musí projít měřením. |
| Označení „užitečné“ | Autonomní běh smí říct „splněno technicky“, ne „užitečné“ (pragmatik); užitečnost potřebuje analytika. |

## 3. Kroky a pořadí

### Fáze 0: opravy před dalším měřením (kód, malé)

| krok | co | hotovo |
|---|---|---|
| F0-1 | Ořez ponechá nejnovější incidenty; počet ořezaných hlásit (stats už je) | test |
| F0-2 | Hub zahrnuje jen nálezy v časovém okně (stupeň se počítá v okně, ne za celou historii) | test: host s 30 nálezy za 2 dny se nerozpadne |
| F0-3 | `has_finding` přes index (HashSet) a aktualizace události o nové důkazy (protějšky, čas poslední změny) | test + výkon |
| F0-4 | Pravidlo (c) nespojuje přes sdílenou oběť (nález bez hosta se nespojí s jiným nálezem bez hosta jen proto, že mají tutéž oběť) | test na kolizi |
| F0-5 | `v3` bez `v2` je explicitní chyba konfigurace, ne tichý návrat k v1 | test |
| F0-6 | Čas události: ověřit, že fáze uvnitř jednoho okna řadí podle času toku, ne vkládání (jinak `ts_flow` do nálezu) | test se třemi fázemi v jednom okně |

### Fáze 1: metodika a nezávislé měření

| krok | co | hotovo |
|---|---|---|
| M1 | Silnější baseline: B1b (IP-union s oknem 6 h a mezí hubu 25), B1c (v2 + pravidlo „protějšek se stane aktérem“), B1d (aktér + okno) | v `k33_corr.py` |
| M2 | Metrika kontaminace: podíl nálezů pozadí v incidentech s řetězcem, slité s pozadím jako chyba; nálezy bez pravdy se vykazují zvlášť | v `k33_corr.py` |
| M3 | Druhý tvar řetězců (fan-out, souběžné útoky ve stejném okně, jedno okno) a kontrola permutovanými rolemi (aktér ↔ oběť) proti naučení na tvar | `k35_chain` generátor |
| M4 | Předregistrace: H2 rozdělena (pozadí samotné; incidenty řetězců), absolutní stropy, nový seed pro každou verzi, jednotky ≥ 60 nebo zvlášť scénáře, nepravdivý výsledek se zapisuje jako negativní | `predreg-krok35.md` |
| M5 | Měření po přeskupení: churn incidentů po oknech (změna členství a klíče), ne jen stav na konci | v `k33_corr.py` |

### Fáze 2: skutečná data (rozhoduje, zda `corr_v3` stojí za provoz)

| krok | co | hotovo |
|---|---|---|
| K9 | `corr_v3` a silné baseline na CTU-13 (dev 42/51/54, test ostatní) a IoT-23. Jednotka scénář; řetěz = (scénář, infikovaný host); fáze podle štítků; nález patří fázi jen podle IP protějšku toku a času ±30 min, ne zmínce; N ≥ 20 scénářů; dolní mez rozdílu proti B1b > 0 permutačním testem. Pravidla zmrazená před stažením dat | `predreg-krok36.md`, `impl-krok36.md` |
| K10 | Šum pozadí na 3denním domácím záznamu: oddělené číslo (incidenty/den bez řetězců); nepotlačovat typy, jen rozhodnout, co je incident zobrazený; absolutní strop předregistrovaný | součást K9 |

### Fáze 3: provoz

| krok | co | hotovo |
|---|---|---|
| K11 | Důvod hrany deklarativně (tabulka pravidel → `links[].reason`), test „žádná hrana bez důvodu“ | test |
| K12 | Zdroj skenu (`srcs` mimo `finding_id`) jen pokud po F0-4 zůstanou slité kolizní dvojice | podmíněně |
| K13 | Persistence po událostech (SQLite místo JSON), stabilní klíč incidentu, idempotence, čítač vyřazených událostí | po 20 přerušeních 0 duplicit a 0 ztrát; zápis ≤ 1 MB/okno; stav ≤ 200 MB za 30 dní; mazání dle retence |
| K15 | Výkon a degradace: reference hardware (Pi 4 nebo N100), 50 000 událostí ≤ 2 s CPU a ≤ 150 MB; při vypnutém zdroji běh nespadne, `coverage_gaps` na incidentu, odchylka počtu ≤ 30 % | měření |
| K14 | Ovládání incidentu: sloučit, rozdělit, nespojovat s auditem; nikdy neměnit závažnost ani zavření chráněných | funkční test (přežije restart) |
| S1 | Souhrn dne: jeden řádek na incident (stabilní ID, hosté, fáze, důvod, časy, „nový od včera“), sbalené opakování, počítadla, příznak neúplného pokrytí | test + vzor výstupu |

### Fáze 4: provozní ověření

| krok | co | hotovo |
|---|---|---|
| K16 | Shadow 14 dní se zapnutou korelací na domácí síti | medián a rozptyl denních incidentů, absolutní strop pozadí, 0 opakovaných zobrazení kvůli nestabilnímu klíči, 0 uzavřených chráněných, 0 změn zobrazení |
| K17 | Rozhodnutí o výchozím profilu podle číselné tabulky (viz §4), ne hlasováním | tabulka vyplněná |

Pořadí: F0 → M1 až M5 → K9+K10 → (K11, K13, K15 paralelně) → K12 podmíněně → K14, S1 → K16 → K17. K9 je rozhodující brána: pokud `corr_v3` nepřekoná silnou baseline na skutečných datech, závěr zní „přínos omezen na syntetický tvar“ a zbývající kroky se přeřadí na opravu produkčního v1 (který je horší než triviální seskupení).

## 4. Kdy je plán „prokazatelně splněn“

1. K9: `corr_v3` překoná silnou baseline B1b na skutečných označených datech, dolní mez rozdílu > 0, na víc scénářích; kontaminace incidentů s útokem nálezy pozadí ≤ předem daný práh.
2. Nikdy se neořízne nejnovější incident; hub se nerozpadá při dlouhé historii; měřeno průběžně přes okna (churn členství a klíče ≤ předem daný podíl).
3. Každá hrana incidentu má zapsaný důvod; žádná nesplněná předregistrovaná hypotéza není přeformulovaná, jen zapsaná jako negativní.
4. Zobrazené nálezy beze změny a 0 uzavřených chráněných v každém měření; nový zdroj v existujícím incidentu znovu zobrazí.
5. Výkon, paměť, zápis, obnova po pádu a degradace splňují čísla z K13 a K15 na určeném hardwaru.
6. K16: 14 dní bez porušení; medián a rozptyl denních počtů v mezích předem daných; autonomní závěr smí říct „technicky splněno“, ne „užitečné pro analytika“.
7. Po každém kroku: dokument kroku, předregistrace před měřením, nepoužitý seed na testu, nezávislé review (jen čtení) u kroků na stavu, souběhu a rozhodování; testy dotčených modulů, `cargo fmt`, stav README, commit a push.

## 5. Meze, které zůstávají

Syntetické řetězce se skutečnými daty nenahradí; skutečné botnety v CTU-13 a IoT-23 mají obvykle jediného škodlivého hosta, takže K9 může ukázat, že přínos `corr_v3` nad jednoduchou baseline je malý. Užitečnost pro analytika se bez analytika neprokáže. 14denní soak trvá 14 dní reálného času.
