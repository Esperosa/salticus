# Implementace, krok 10: poučení z chyb a zobecnění na neznámé útoky

Datum 2026-11-14. Navazuje na krok 9 (`impl-krok9.md`). Projekt: Salticus.

Poctivost: 100 % se neslibuje. Co se nepodaří, je v registru (sekce E) jako otevřené. Část „tvrdší testování“ je zde předregistrována; hodnoty se po prvním měření nemění.

## A) Smyčka chyba → poučení

1. **Záznam je abstraktní.** `analyst_feedback::Lesson` a `tools/soak_k10.py` ukládají jen třídy rysů: taktika ATT&CK, protokol, třída portu, tempo, objem, topologie, počet zdrojů, viditelnost IDS, selhaná kontrola. Uzavřené slovníky (`analyst_feedback::{CLASSES, TEMPOS, ...}`) znemožňují uložit adresu, seed nebo identifikátor sítě; validace to odmítne a server vrací 422.
2. **Korpus a společné příčiny.** `soak_k10.py` shlukuje chyby podle kombinace rysů, počítá podíl chyb a „lift“ proti základu s Wilsonovým intervalem (`k10/causes.md`) a z nejčastějších shluků zapisuje parametrické regresní scénáře (`k10/corpus.jsonl`, jen abstraktní rysy). Scénář je popis chování, ne záznam provozu.
3. **Zákaz paměti.** Test `no_memory` v `soak::variants::tests` ověřuje, že produkční zdrojový kód (mimo testy a dokumentaci) neobsahuje seedy použité v měření ani adresy generátoru. Druhý test (`breadth` s jinými adresami) ověřuje, že se stejné chování na jiných adresách chová stejně.

## B) Provozní zpětná vazba (API a hook UI)

- `POST /api/feedback` přijímá poučení typu `missed_attack` („tohle jsem měl vidět“), `wrong_closed`, `misclassified`, `confirmed_ok`; `GET /api/feedback` vrací aktivní záznamy a souhrn; `POST /api/feedback/{id}/revoke` záznam odvolá. Oprávnění `findings.write`, CSRF, jako u ostatních verdiktů.
- Úložiště je append-only (SQLite triggery); odvolání je nový řádek, původní zůstává (audit a vratnost).
- Projekce do provozu je doporučení: kalibrační přirážka nejistoty druhu a návrh vypnutí automatického zavírání druhu po `DISABLE_AT` = 3 omylem zavřených. Vypnutí provádí stávající `closure_audit`, nic se nezapíná samo.

## C) Neznámé rodiny (taktiky a chování)

Detektory kroku 9 (`behavior::breadth`) i stávající behaviorální vrstva neznají rodinu, jen rys chování. Vyhodnocení po taktikách (ATT&CK) je v tabulce `k10/taktiky.md`.

### Protokol leave-one-tactic-out a leave-one-family-out (předregistrace)

Fold LOTO (taktiky, jejichž rodiny se při ladění detektorů kroku 9 ani 10 nesledovaly): `credential-access`, `discovery`, `lateral-movement`. Fold LOFO (rodiny): `c2_slow_long_interval`, `ssh_spray_slow_distributed`, `data_staging_smb_internal`, `kerberos_ticket_request_burst`, `ics_attack`, `cloud_api_discovery_burst`, `rdp_bruteforce`, `ddos_syn_flood_distributed`. Pravidla:

- při ladění detektorů se tyto rodiny a taktiky nepoužijí ani jako kritérium (rozhodnutí o prazích se opírají o metriku ladicí podmnožiny bez nich),
- po zamčení detektorů se vyhodnotí jednou na ladicích a pak na držených seedech,
- přiznané omezení: rodiny ostatních taktik byly viděny při návrhu (tabulka kroku 9 před detektory), takže LOFO zde měří odolnost detektorů vůči neviděným rodinám, ne plnou nezávislost návrhu.

### Prahy

| práh | definice | splněno, když |
|---|---|---|
| K10-1 | detekce v LOFO a LOTO foldu | ≥ 90 % a dolní mez Wilsonova intervalu ≥ 85 %; jinak výslovně v seznamu „nedosaženo“ |
| K10-2 | novost se nikdy nezavírá automaticky | 0 chráněných zavření (stejné jako K9-5) |
| K10-3 | zákaz paměti | testy `no_memory` a nezávislost na adresách zelené |
| K10-4 | zpětná vazba | API testy: odmítnutí adres, append-only, odvolání, souhrn nevypíná sám |
| K10-5 | kombinace (útok + porucha + šum 10 × + výpadek senzoru) | detekce útoků nižší nejvýš o 5 p. b. než bez kombinace; zavřeno omylem ≤ 2,2 % |
| K10-6 | tvrdé záporné scénáře (neškodné, ale podobné útoku) | FP zobrazené na síť-den ≤ 1,15 × krok 9; klasifikace záporných jako útok ≤ 15 % |
| K10-7 | stres XXXL | 0 paniků, p99 doby cyklu ≤ stropu kroku 8, paměť bez růstu |
| K10-8 | drift v čase | detekce v druhé polovině běhu nižší nejvýš o 3 p. b. než v první |
| K10-9 | determinismus a kompatibilita | jako K9-6 |

Měření na ladicích seedech 20262301 a 20262302 plus nových 20262401, 20262402; držené (viz krok 9) se pouští jednou na konci.

## D) Měření

(vyplní se po měření)

## E) Registr otevřených míst

(vyplní se po měření)
