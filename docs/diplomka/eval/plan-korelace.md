# Plán korelace (krok 33 a dál)

Vznikl ze tří nezávislých rozborů kódu a dokumentů: architekt korelace, skeptik a metrolog, pragmatik provozu. Všichni tři došli ke stejnému jádru a hlavní tvrzení jsem před zápisem ověřil v kódu.

## 1. Společný nález

Korelace se dosud nikde neměřila. Kroky 26 až 32 měří jen to, zda se IP útočníka objeví v zobrazeném nálezu. Produkce (`correlation_layer::run`) přitom:

- zapisuje do historie čas běhu (`ts: now`), ne čas nálezu, takže pořadí fází nemá kauzální smysl;
- přidává událost při každém zobrazení téhož nálezu a filtr `findings.len() > 1` pak počítá události, ne různé nálezy (jeden trvající nález ve dvou oknech může tvořit „incident“);
- používá seskupování v1 (sdílený host slévá nesouvisející nálezy); v2 se volá jen v soaku;
- tiše zahazuje nálezy bez `host_key`, osamělé skupiny i nálezy nad strop 200;
- číslo incidentu je pořadí v běhu (nestabilní), důvod spojení se nezapisuje.

## 2. Co se bude dělat (pořadí a hotovo)

| # | krok | velikost | kritérium hotovo |
|---|---|---|---|
| K1 | Oprava korelace za přepínačem `corr_v2` (čas nálezu, jedna událost na nález, seskupení v2, různé nálezy, stabilní klíč, čítače zahozených) | S | testy; chování bez přepínače beze změny |
| K2 | Vícefázové vložené řetězce s pravdou po řetězech (`k25_inject.py chain`: sken, hrubá síla na cíl, výstup z kompromitovaného hostu; pivot přes dvě IP, souběžné řetězce na společný server) | M | `truth_chain.json`, generátor zmrazen hashem commitu |
| K3 | Vyhodnocení `corr_eval.py`: čistota, slévání, úplnost, fragmentace, B-cubed F1 přes dvojice z různých fází, komprese, ztráta zachycení, 95 % intervaly (bootstrap) | M | běží nad výstupem K2 |
| K4 | Předregistrace `predreg-krok33.md` před měřením: ramena B0 bez korelace, B1 jen podle IP, B2 náhodné seskupení se stejnými velikostmi, B3 v1, B4 v2 (`corr_v2`); H1 bez ztráty zachycení, H2 šum, H3 zisk proti B1 i B2 | S | commit před měřením |
| K5 | Jedno měření na nových seedech (dev a test odděleně), honest report | L | `impl-krok33.md` |
| K6 | Podle výsledku: důvod spojení na každé hraně incidentu, strukturované indikátory (community_id, doména, SNI) místo regexu, retence stavu po událostech a ne jeden JSON | M | podle K5 |
| K7 | Ovládání incidentu (sloučit, rozdělit, nespojovat) s auditem, nikdy neměnit závažnost ani zavření | M | přežije restart |
| K8 | Soak na domácí síti se zapnutou korelací, provozní kritéria níže | L | 14 dní |

Co se vědomě nedělá: další detekční pravidla, další datasety, ATT&CK po technikách, automatické slučování identit podle otisku (slučuje se jen případ, ne asset), cluster a HA.

## 3. Hranice, které se nesmí porušit

- Korelace jen anotuje; nezavírá ani nepotlačuje nález (chráněné a High se nikdy nepotlačují).
- Nový zdroj v existujícím incidentu znovu zobrazí.
- Prázdný řetěz znamená „nebylo pozorováno“, ne „neškodné“; slepá místa se hlásí.
- Žádné ladění na testovacích datech. Okna a prahy se zmrazí před testem a změna je nový krok s novým rozdělením.

## 4. Hypotézy (shrnutí, přesné prahy až v predreg)

- H1: B4 nezmenší počet zachycených řetězců proti B0 (horní mez ztráty 5 % z Wilsonova intervalu).
- H2: na domácí síti bez útoků ≤ 15 incidentů za den; na čistém pozadí žádný smíšený incident.
- H3: B4 překoná B1 i B2 v B-cubed F1 přes dvojice z různých fází o ≥ 0,1 (párový bootstrap přes řetězce). Čistota sama nestačí, protože seskupení jen podle IP ji má při unikátních IP útočníků triviálně 1,0.

## 5. Provozní kritéria před zapnutím ve výchozím profilu

Největší incident ≤ 20 % zobrazených nálezů dne; žádná hrana bez důvodu; zachycení 8 rodin stále 10/10 i s druhým útočníkem; 0 uzavřených chráněných nálezů; opakování okna dává shodný výstup; po 20 náhodných přerušeních 0 duplicitních a 0 ztracených incidentů; ≤ 2 s CPU a ≤ 150 MB na 50 000 událostí; zápis za okno ≤ 1 MB; při vypnutém zdroji běh nespadne a incident hlásí mezery pokrytí.

## 6. Neshody mezi agenty a rozhodnutí

- Architekt chtěl hned entitní graf; pragmatik a skeptik: nejdřív měřit, co dnes je. Rozhodnuto: nejdřív K1 až K5, graf (L1 až L4) jen pokud K5 ukáže, že v2 nestačí.
- Pragmatik chtěl zapnout `attempts`, `attr_calib`, `upload_horizon`, `case_files` ve výchozím profilu; skeptik upozornil, že všechna měření jsou na vývojových datech. Rozhodnuto: o výchozím profilu až po K5 a K8 na neviděných seedech.
