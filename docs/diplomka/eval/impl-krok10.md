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

Stav k 2026-11-14. Implementováno a otestováno (jednotkové testy zelené): abstraktní záznamy a API zpětné vazby (`analyst_feedback`, K10-4), zákaz paměti seedů (`soak::no_memory`, K10-3), nástroj smyčky chyba → poučení (`tools/soak_k10.py`; výstup `k10/causes.md`, `k10/corpus.jsonl`, `k10/lessons.jsonl`), svět `--coverage k10` se 8 tvrdými zápornými scénáři (neškodné, ale tvarem podobné útoku: noční záloha do cloudu, stažení aktualizací, monitorovací SNMP sweep, synchronizace hesel, hromadné SSH správce, replikace databáze, hromadná pošta, autorizovaný interní sken) a vyhodnocení neviděných taktik a rodin podle předregistrovaných foldů (`k9_final.py`, sekce „Neviděné taktiky a rodiny“ v `k9/vysledky.md`).

Běhy ve frontě (jedno rameno najednou, Idle, 4 vlákna), vyhodnocení jedním příkazem `python tools/k9_finish.py`:

| úloha | běh | výstup |
|---|---|---|
| K10-6 tvrdé záporné scénáře, nové seedy | `k10ref`, `k10c` na 20262401, 20262402 | `k10/vysledky.md` |
| K10-5 kombinace s šumem 10× | `noise10ref`, `noise10` na 20262301 | `k10/sum10x.md` |
| K10-7 stres XXXL | `xxxlc` (3 sítě třídy XXXL, 20262302) | výpis `final-report.md` v `F:/Projekty/bakula-soak/k9/xxxlc-20262302` (paniky, `cycle_p99_s`, paměť) |
| K10-1 neviděné taktiky a rodiny | z běhů kroku 9 | `k9/vysledky.md` |
| K10-8 drift v čase | rozdělení běhů na první a druhou polovinu | neměřeno; generátor nemá vestavěný drift, takže je to otevřené (kategorie c) |
| držené seedy | `heldref`, `heldc` | `k9/held.md` (jednou) |

Mezivýsledek K10-1 (seedy 20261102 a 20261103, 80 sítí): taktika `lateral-movement` 93,5 % (dolní mez 89,7, splněno), `credential-access` 86,8 % a `discovery` 85,9 % (nedosaženo); rodiny jednotlivě mají n < 50 (nedostatek dat). Poctivé omezení: detektory kroku 9 se na těchto foldech neladěly, ale celé pole rodin jsem viděl při návrhu, takže jde o odolnost detektorů, ne o plnou nezávislost.

### Výsledky měření (2026-11-14)

| práh | výsledek | stav |
|---|---|---|
| K10-6 tvrdé záporné scénáře (`k10/vysledky.md`, 80 sítí, 20262401 a 20262402) | zobrazené FP na síť-den 10,37 → 10,86, poměr 1,048 (1,029 až 1,071) ≤ 1,15; zavřeno omylem 0,5 %; chráněná zavření 0, paniky 0. Zobrazování neškodných změn (kandidát): hn_cdn_update_download 6,5 %, hn_mail_newsletter_burst 7,5 %, hn_nightly_cloud_backup_upload 48,2 %, hn_db_replication_bulk 79,0 %, hn_admin_bulk_ssh 82,9 %, hn_monitoring_snmp_sweep 83,1 % | FP splněno; „klasifikace záporných jako útok ≤ 15 %“ se zvlášť neměřila (tabulka udává podíl zobrazených), u čtyř rodin je zobrazeno většina případů, takže nepotvrzeno (c) |
| K10-5 šum 10× + porucha + výpadek (`k10/sum10x.md`, 40 sítí, 20262301) | detekce 82,3 % (základ 81,5 %); proti ladicím seedům kandidáta 84,7 % je to −2,4 p. b. (jiná množina seedů, jen orientačně) ≤ 5 p. b.; zavřeno omylem 0,9 % ≤ 2,2 %; FP poměr 1,080; paniky 0 | splněno (orientačně) |
| K10-7 XXXL (`xxxlc-20262302`, 4 sítě XXXL, 384 cyklů, 15,1 mil. toků, 4 vlákna, stroj zatížený dlouhým během) | paniky 0, porušené invarianty 0; p99 cyklu 3,17 s (p50 1,95 s, max 4,71 s) proti stropu 3 s kroku 7 (G4, 1 vlákno, klidný stroj); peak haldy 2 145 MiB, RSS na konci 45 MiB, bez růstu, ale jen 3 vzorky | p99 těsně nad stropem při zatíženém stroji a 4 vláknech (podmínky G4 nesplněny): **nesplněno, nerozhodnuto** |
| K10-1 neviděné taktiky (držené seedy, `k9/held.md`) | credential-access 90,5 % (splněno), lateral-movement 94,9 % (splněno), discovery 83,5 % (nedosaženo); rodiny n ≥ 50: ssh_spray_slow_distributed 85,5 %, data_staging_smb_internal 82,4 %, c2_slow_long_interval 87,0 %, cloud_api_discovery_burst 9,2 %, ddos_syn_flood_distributed 91,4 % s dolní mezí pod 85 % (nedosaženo), kerberos_ticket_request_burst 98,9 % a rdp_bruteforce 98,8 % (splněno) | částečně |
| K10-8 drift | neměřeno | (c) |

## E) Registr otevřených míst

| místo | kategorie |
|---|---|
| Zachycení neznámé rodiny taktikou/chováním nad 90 % | splněno jen u `lateral-movement`; `credential-access` a `discovery` kolem 86 % (c) |
| Drift v čase (K10-8) | neměřeno (c) |
| Zpětná vazba nemění kalibraci automaticky | jen doporučení (`Summary`): přirážka nejistoty a návrh vypnutí zavírání; napojení na kalibraci jádra je navazující krok (c) |
| Řetěz nezávislých kontrol (`verification_chain`) není napojen na žebřík | modul je samostatný, testovaný; simulace nemá DNS ani TLS data, takže přínos nelze změřit (c) |
| Korpus regresních scénářů se zatím negeneruje zpět do soaku | `corpus.jsonl` je abstraktní popis; mapování na `SPECS` je navazující krok (c) |
